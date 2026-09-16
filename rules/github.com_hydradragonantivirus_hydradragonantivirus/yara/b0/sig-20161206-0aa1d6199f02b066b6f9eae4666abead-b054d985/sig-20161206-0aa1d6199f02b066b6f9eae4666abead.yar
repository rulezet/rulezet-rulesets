rule sig_20161206_0aa1d6199f02b066b6f9eae4666abead {
  meta:
    description = "datamaliciousorder - file 20161206_0aa1d6199f02b066b6f9eae4666abead.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f64a7a052186d5f2ce049fe6693d118809bf58fe2741ef3537ab046872d46b2f"

  strings:
    $s1 = "var vVl5 = new Function(\"s\", '{var vNj8 = new Date();vNj8[\"setUTCFullYear\"](\"2003\");if (vNj8.getUTCFullYear().toString(10)" ascii
    $s2 = "var vVl5 = new Function(\"s\", '{var vNj8 = new Date();vNj8[\"setUTCFullYear\"](\"2003\");if (vNj8.getUTCFullYear().toString(10)" ascii
    $s3 = "003\") {var vIWc3 = s.split(\"##\"); return vIWc3.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vQk3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}