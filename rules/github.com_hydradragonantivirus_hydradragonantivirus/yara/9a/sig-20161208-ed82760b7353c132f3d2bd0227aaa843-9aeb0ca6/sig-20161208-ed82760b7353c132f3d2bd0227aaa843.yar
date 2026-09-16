rule sig_20161208_ed82760b7353c132f3d2bd0227aaa843 {
  meta:
    description = "datamaliciousorder - file 20161208_ed82760b7353c132f3d2bd0227aaa843.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6749f1c84a9ad400c8fda0aaa9ca886c3be8799d0658caa36eab3f129bfba421"

  strings:
    $s1 = "7 = new Date();vDo7[\"setUTC\"+\"FullYear\"](\"2003\");if (vDo7.getUTCFullYear().toString(10) == \"2003\") {var vWx0 = vHGi5.spl" ascii
    $s2 = "var vGTt0 = new Function(\"vHGi5\", '{return vHGi5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGIr2 = new Function(\"vH" ascii
    $s3 = "\"); return vWx0.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vGTt0 = new Function(\"vHGi5\", '{return vHGi5[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vGIr2 = new Function(\"vH" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}