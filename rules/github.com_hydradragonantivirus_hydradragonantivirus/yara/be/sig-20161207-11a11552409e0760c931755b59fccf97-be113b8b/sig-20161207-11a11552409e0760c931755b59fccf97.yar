rule sig_20161207_11a11552409e0760c931755b59fccf97 {
  meta:
    description = "datamaliciousorder - file 20161207_11a11552409e0760c931755b59fccf97.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42ad7cdc38b3b6a3b0e6385b9142062fe42838a0257c49905861ca4f50b18b35"

  strings:
    $s1 = "var vDq7 = new Function(\"vZFc9\", '{return vZFc9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJYa1 = new Function(\"vZF" ascii
    $s2 = " = new Date();vAj7[\"setUTCFullYear\"](\"2003\");if (vAj7.getUTCFullYear().toString(10) == \"2003\") {var vLq0 = vZFc9.split(\"#" ascii
    $s3 = "return vLq0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vDq7 = new Function(\"vZFc9\", '{return vZFc9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vJYa1 = new Function(\"vZF" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}