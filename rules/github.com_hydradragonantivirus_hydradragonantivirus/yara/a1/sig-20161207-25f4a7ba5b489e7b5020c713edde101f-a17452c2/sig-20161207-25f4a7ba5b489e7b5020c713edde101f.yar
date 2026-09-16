rule sig_20161207_25f4a7ba5b489e7b5020c713edde101f {
  meta:
    description = "datamaliciousorder - file 20161207_25f4a7ba5b489e7b5020c713edde101f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd4ff504b0a3c696c049dd0db82d35a1da2f821bff7634ade5a863001eaa17c5"

  strings:
    $s1 = "var vOs8 = new Function(\"vKj7\", '{var vOj8 = new Date();vOj8[\"setUTCFullYear\"](\"2003\");if (vOj8.getUTCFullYear().toString(" ascii
    $s2 = "var vOs8 = new Function(\"vKj7\", '{var vOj8 = new Date();vOj8[\"setUTCFullYear\"](\"2003\");if (vOj8.getUTCFullYear().toString(" ascii
    $s3 = "var vPLz2 = new Function(\"vKj7\", '{return vKj7.split(\",\").join(\"\");};');" fullword ascii
    $s4 = " \"2003\") {var vNKx4 = vKj7.split(\"###\"); return vNKx4.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}