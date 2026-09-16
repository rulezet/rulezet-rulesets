rule sig_20161206_3f6ff509b4920eeff854b71aebea1f0d {
  meta:
    description = "datamaliciousorder - file 20161206_3f6ff509b4920eeff854b71aebea1f0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a73628899bd52d91f1bb2c9c34beb0acbafc73ec5756ccf3cf8b5d466ceeebca"

  strings:
    $s1 = "var vIGj4 = new Function(\"s\", '{var vEg8 = new Date();vEg8[\"setUTCFullYear\"](\"2003\");if (vEg8.getUTCFullYear().toString(10" ascii
    $s2 = "var vIGj4 = new Function(\"s\", '{var vEg8 = new Date();vEg8[\"setUTCFullYear\"](\"2003\");if (vEg8.getUTCFullYear().toString(10" ascii
    $s3 = "2003\") {var vDy5 = s.split(\"##\"); return vDy5.join(\"\");} else return \"\";};');" fullword ascii
    $s4 = "function vDCw9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}