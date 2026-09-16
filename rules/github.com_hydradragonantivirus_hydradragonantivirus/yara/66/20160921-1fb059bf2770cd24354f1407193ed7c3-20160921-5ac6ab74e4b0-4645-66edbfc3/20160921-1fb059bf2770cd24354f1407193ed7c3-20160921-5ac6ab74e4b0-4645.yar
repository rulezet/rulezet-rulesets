rule _20160921_1fb059bf2770cd24354f1407193ed7c3_20160921_5ac6ab74e4b0_4645 {
  meta:
    description = "datamaliciousorder - from files 20160921_1fb059bf2770cd24354f1407193ed7c3.js, 20160921_5ac6ab74e4b06b9e82f957e9e7bf6669.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca19a6205a8df61781b8acbf540faa9dd7bc11338d9b2e4285541a5ac284f620"
    hash2       = "50225d12c51a2decb97015971f8ce72487a24a69e64ec1d12fd7f720f2320cf3"

  strings:
    $s1 = "})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"EZu\";})(),(function f000" ascii
    $s2 = "on f000(){return \"Ml\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"" ascii
    $s3 = "ction f000(){return \"WIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oh\";})(),(function f000(){retur" ascii
    $s4 = "),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000()" ascii
    $s5 = "n \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Vj\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}