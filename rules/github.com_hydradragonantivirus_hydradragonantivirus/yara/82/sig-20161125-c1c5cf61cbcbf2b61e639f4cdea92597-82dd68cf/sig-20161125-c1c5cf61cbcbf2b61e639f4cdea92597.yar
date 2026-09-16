rule sig_20161125_c1c5cf61cbcbf2b61e639f4cdea92597 {
  meta:
    description = "datamaliciousorder - file 20161125_c1c5cf61cbcbf2b61e639f4cdea92597.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c47426644395ba00feaeef8a44e93132f2ac18851a9048b904c30f59c5d4ac7"

  strings:
    $s1 = "ojapfa[yztety].irenz = new Function(\"return ojapfa[yztety]\" + zaqilo)();" fullword ascii
    $s2 = "var ikahxapeb6 = [\"a\", \"kj\", \"o\", \"e\", \"ln\", \"d\", \"jp\", \"u\", \"u\", \"o\", \"i\", \"u\", \"u\", new Function([\"" ascii
    $s3 = "var ugulde = [\"rb\", \"i\", \"e\", \"e\", \"e\", \"u\", \"e\", \"mw\", \"e\", \"e\", \"o\", \"qv\", new Function([\"k\", \"nl\"" ascii
    $s4 = "var ojapfa = Array;" fullword ascii
    $s5 = "var ikahxapeb6 = [\"a\", \"kj\", \"o\", \"e\", \"ln\", \"d\", \"jp\", \"u\", \"u\", \"o\", \"i\", \"u\", \"u\", new Function([\"" ascii
    $s6 = "var osapfym0 = [\"gd\", \"o\", \"s\", \"wd\", \"d\", \"qq\", \"x\", \"i\", \"zz\", this].irenz();" fullword ascii
    $s7 = "var ugulde = [\"rb\", \"i\", \"e\", \"e\", \"e\", \"u\", \"e\", \"mw\", \"e\", \"e\", \"o\", \"qv\", new Function([\"k\", \"nl\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}