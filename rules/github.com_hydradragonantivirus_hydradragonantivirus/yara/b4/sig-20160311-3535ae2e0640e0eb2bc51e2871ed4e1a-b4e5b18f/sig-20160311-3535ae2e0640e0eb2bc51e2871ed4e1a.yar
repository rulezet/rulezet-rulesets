rule sig_20160311_3535ae2e0640e0eb2bc51e2871ed4e1a {
  meta:
    description = "datamaliciousorder - file 20160311_3535ae2e0640e0eb2bc51e2871ed4e1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5577974c92afcbcea5dfcd6e739255a09d3e8f031a52712d3d3e60123e5acaa"

  strings:
    $s1  = "pdataOld[qsaError + \"en\"](settings + \"ET\", rdashAlpha + \"/pe\".stopped() + ontype + \"kem.\" + factory + \"877\" + relative" ascii
    $s2  = "classes = hasCompare[doc + \"andEn\" + charset + \"entS\".stopped() + getScript + \"ngs\"](createPseudo + \"%/\") + realStringOb" ascii
    $s3  = "classes = hasCompare[doc + \"andEn\" + charset + \"entS\".stopped() + getScript + \"ngs\"](createPseudo + \"%/\") + realStringOb" ascii
    $s4  = "_default = \"e\", matchAnyContext = \"ite\", getScript = \"tri\", realStringObj = \"margin\", relative = \"45g\";" fullword ascii
    $s5  = "5 / cssNumber))) - 2 * (extra - 31) * mouseenter * (1 * mouseenter) * 2 * (namespaces * 2)))) == _load));" fullword ascii
    $s6  = "rchecked[radioValue + \"n\"](classes.stopped(((129 | stored), 31 * preexisting * 2, (Math.pow(prototype, 2) - response), 89)), (" ascii
    $s7  = "rchecked[radioValue + \"n\"](classes.stopped(((129 | stored), 31 * preexisting * 2, (Math.pow(prototype, 2) - response), 89)), (" ascii
    $s8  = "pdataOld[qsaError + \"en\"](settings + \"ET\", rdashAlpha + \"/pe\".stopped() + ontype + \"kem.\" + factory + \"877\" + relative" ascii
    $s9  = "hasCompare = returnFalse[flag + \"eObjec\" + uniqueSort](\"WScrip\".stopped() + one + \"hell\");" fullword ascii
    $s10 = "pdataOld = etag[\"WSc\" + list][\"Creat\".stopped() + propFix + \"ct\"](mozMatchesSelector + \"L2.X\" + adjustCSS + \"P\".stoppe" ascii
    $s11 = "_data = etag[success + \"pt\"][col + \"ate\".stopped() + elems + \"ct\"](speed + \"B.S\" + filters + \"m\".stopped());" fullword ascii
    $s12 = "invert[duration + \"e\"]();" fullword ascii
    $s13 = "var prefilterOrFactory = this;" fullword ascii
    $s14 = "function radio() {" fullword ascii
    $s15 = "mozMatchesSelector = \"MSXM\", radioValue = \"Ru\", extra = 33, flag = \"Creat\", s = \"ty\";" fullword ascii
    $s16 = "duration = \"clos\"," fullword ascii
    $s17 = "return prefilterOrFactory" fullword ascii
    $s18 = "invert = _data;" fullword ascii
    $s19 = "col = \"Cre\", serialize = \"pos\";" fullword ascii
    $s20 = "var speed = \"ADOD\"," fullword ascii

  condition:
    uint16(0) == 0x645f and
    8 of them
}