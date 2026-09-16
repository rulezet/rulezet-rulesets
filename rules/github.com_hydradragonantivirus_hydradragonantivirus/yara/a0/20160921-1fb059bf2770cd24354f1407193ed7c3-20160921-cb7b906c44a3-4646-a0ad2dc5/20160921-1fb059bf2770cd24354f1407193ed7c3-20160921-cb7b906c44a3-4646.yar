rule _20160921_1fb059bf2770cd24354f1407193ed7c3_20160921_cb7b906c44a3_4646 {
  meta:
    description = "datamaliciousorder - from files 20160921_1fb059bf2770cd24354f1407193ed7c3.js, 20160921_cb7b906c44a337d403a375918e9db0c5.js, 20160921_e0e06f5c94b0cde962f3e4c452e69af8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca19a6205a8df61781b8acbf540faa9dd7bc11338d9b2e4285541a5ac284f620"
    hash2       = "2a06a7a374bfacf6c8c177295f8ab5c8e4e8db511406cc33fcef97866f72f9dc"
    hash3       = "c9140c7affc44d690abfb95dc146d3e298e2cfddacedfee85549119f368d56d1"

  strings:
    $s1 = "tion f000(){return \"Br\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return " ascii
    $s2 = "})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Br\";})(),(function f000" ascii
    $s3 = " \"DIa\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"DYx\";})(),(func" ascii
    $s4 = "0(){return \"Vj\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Oe\";" ascii
    $s5 = "nction f000(){return \"Tn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yz\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}