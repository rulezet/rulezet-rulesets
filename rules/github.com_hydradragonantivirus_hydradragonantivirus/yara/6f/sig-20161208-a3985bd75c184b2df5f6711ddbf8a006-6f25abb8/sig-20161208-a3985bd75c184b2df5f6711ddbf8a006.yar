rule sig_20161208_a3985bd75c184b2df5f6711ddbf8a006 {
  meta:
    description = "datamaliciousorder - file 20161208_a3985bd75c184b2df5f6711ddbf8a006.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12acd0c558b339585299f3f35288fe6cdf90c4c6ba178d23694603ee279bd8e5"

  strings:
    $s1 = "1 = new Date();vPRa1[\"setUTC\"+\"FullYear\"](\"2003\");if (vPRa1.getUTCFullYear().toString(10) == \"2003\") {var vAWc5 = vSZd9." ascii
    $s2 = "var vMHz5 = new Function(\"vSZd9\", '{return vSZd9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGa8 = new Function(\"vSZ" ascii
    $s3 = "var vMHz5 = new Function(\"vSZd9\", '{return vSZd9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGa8 = new Function(\"vSZ" ascii
    $s4 = "###\"); return vAWc5.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}