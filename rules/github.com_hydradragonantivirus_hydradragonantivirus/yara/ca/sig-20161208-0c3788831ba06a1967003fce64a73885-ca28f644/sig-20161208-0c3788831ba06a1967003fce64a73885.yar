rule sig_20161208_0c3788831ba06a1967003fce64a73885 {
  meta:
    description = "datamaliciousorder - file 20161208_0c3788831ba06a1967003fce64a73885.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c609373bfb559ec421b49bca5bdf2c2f861301b530ee382b9af010bca222656"

  strings:
    $s1 = "var vRGp4 = new Function(\"vKx5\", '{return vKx5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUMq4 = new Function(\"vKx5" ascii
    $s2 = "= new Date();vEXd9[\"setUTC\"+\"FullYear\"](\"2003\");if (vEXd9.getUTCFullYear().toString(10) == \"2003\") {var vHi1 = vKx5.spli" ascii
    $s3 = "); return vHi1.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vRGp4 = new Function(\"vKx5\", '{return vKx5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vUMq4 = new Function(\"vKx5" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}