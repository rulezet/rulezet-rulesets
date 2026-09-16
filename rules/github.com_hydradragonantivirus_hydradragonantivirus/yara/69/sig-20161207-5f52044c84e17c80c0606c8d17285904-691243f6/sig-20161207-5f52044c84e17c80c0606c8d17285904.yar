rule sig_20161207_5f52044c84e17c80c0606c8d17285904 {
  meta:
    description = "datamaliciousorder - file 20161207_5f52044c84e17c80c0606c8d17285904.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24d4287f479a360a761fde6cbc29d4a66589de14e02f1cd7dab05b5cdf5e269b"

  strings:
    $s1 = "= new Date();vSZs3[\"setUTCFullYear\"](\"2003\");if (vSZs3.getUTCFullYear().toString(10) == \"2003\") {var vUd2 = vJp2.split(\"#" ascii
    $s2 = "var vIYt7 = new Function(\"vJp2\", '{return vJp2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAJv2 = new Function(\"vJp2" ascii
    $s3 = "return vUd2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vIYt7 = new Function(\"vJp2\", '{return vJp2[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vAJv2 = new Function(\"vJp2" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}