rule sig_20161208_545d514c481eb07650717adb24deeb58 {
  meta:
    description = "datamaliciousorder - file 20161208_545d514c481eb07650717adb24deeb58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba9dee72c57b10c7ab21d2c07d39f40a84dc5af95933df54b4c35b0f81f816cb"

  strings:
    $s1 = "var vNPr8 = new Function(\"vLm1\", '{return vLm1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQGq7 = new Function(\"vLm1" ascii
    $s2 = "= new Date();vVJu1[\"setUTC\"+\"FullYear\"](\"2003\");if (vVJu1.getUTCFullYear().toString(10) == \"2003\") {var vTSk9 = vLm1.spl" ascii
    $s3 = "\"); return vTSk9.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vNPr8 = new Function(\"vLm1\", '{return vLm1[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vQGq7 = new Function(\"vLm1" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}