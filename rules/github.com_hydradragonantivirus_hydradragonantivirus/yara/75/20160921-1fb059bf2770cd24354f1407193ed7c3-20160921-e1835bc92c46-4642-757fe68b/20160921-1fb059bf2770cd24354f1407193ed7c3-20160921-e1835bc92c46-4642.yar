rule _20160921_1fb059bf2770cd24354f1407193ed7c3_20160921_e1835bc92c46_4642 {
  meta:
    description = "datamaliciousorder - from files 20160921_1fb059bf2770cd24354f1407193ed7c3.js, 20160921_e1835bc92c4604db194bc49df621cade.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca19a6205a8df61781b8acbf540faa9dd7bc11338d9b2e4285541a5ac284f620"
    hash2       = "ca98fbe0aef0208d6ee3df93c692fee8802fb2206893dc56e723bc4af714c0fd"

  strings:
    $s1 = " f000(){return \"Sv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"G" ascii
    $s2 = "{return \"WIj\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})" ascii
    $s3 = "\"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Kw\";})(),(func" ascii
    $s4 = "rn \"OMd\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(f" ascii
    $s5 = "tion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}