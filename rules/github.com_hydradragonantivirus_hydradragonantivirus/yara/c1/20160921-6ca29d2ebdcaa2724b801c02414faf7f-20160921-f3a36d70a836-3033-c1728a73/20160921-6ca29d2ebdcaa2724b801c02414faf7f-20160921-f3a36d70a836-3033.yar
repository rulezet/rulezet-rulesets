rule _20160921_6ca29d2ebdcaa2724b801c02414faf7f_20160921_f3a36d70a836_3033 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ca29d2ebdcaa2724b801c02414faf7f.js, 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b810435d98ebab77ad9d2cd316e2a0c0211b0941d86cbfa6c0e753732c6d3b15"
    hash2       = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"

  strings:
    $s1 = "\"SGs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa\";})(),(fun" ascii
    $s2 = "unction f000(){return \"UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){ret" ascii
    $s3 = "Ti\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"EZu\";})(),(function" ascii
    $s4 = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Nx\"" ascii
    $s5 = "n \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Sq\";})(),(func" ascii
    $s6 = "Sj\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"MBb\";})(),(function" ascii
    $s7 = "on f000(){return \"ZGq\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}