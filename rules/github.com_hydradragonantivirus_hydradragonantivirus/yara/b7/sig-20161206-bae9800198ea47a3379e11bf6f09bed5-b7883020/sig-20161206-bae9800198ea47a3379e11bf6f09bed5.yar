rule sig_20161206_bae9800198ea47a3379e11bf6f09bed5 {
  meta:
    description = "datamaliciousorder - file 20161206_bae9800198ea47a3379e11bf6f09bed5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42b778f4ee20e2ef5674282e95b0f85b68be0b9304fc61da74e9f553e56a8486"

  strings:
    $s1 = "var vLRv3 = new Function(\"s\", '{var vWKp5 = new Date();vWKp5[\"setUTCFullYear\"](\"2003\");if (vWKp5.getUTCFullYear().toString" ascii
    $s2 = "var vLRv3 = new Function(\"s\", '{var vWKp5 = new Date();vWKp5[\"setUTCFullYear\"](\"2003\");if (vWKp5.getUTCFullYear().toString" ascii
    $s3 = "function vQy8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii
    $s4 = "= \"2003\") {var vTb8 = s.split(\"##\"); return vTb8.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}