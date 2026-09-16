rule _20160921_802181e3d75c3e2d045cebba97849683_20160921_ba8a9f239804_3943 {
  meta:
    description = "datamaliciousorder - from files 20160921_802181e3d75c3e2d045cebba97849683.js, 20160921_ba8a9f239804499b5d1d2a06a862c1ca.js, 20160921_ee1327bdf201e62d1f7ae5482cabbd90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab42f16384f05ce6299f1ffd60f980af6ecf1fa2d23befc951797d1d52915400"
    hash2       = "4ab28724a794acc5764f2e51f93d2b91ef9513b43e4cb9b0d10bad2710c2e6d7"
    hash3       = "91500ac726f9d2548dffc99162aeece9863dc7b928106d27a769e6bbf9439f81"

  strings:
    $s1 = "function f000(){return \"Lo\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){re" ascii
    $s2 = "00(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Yv" ascii
    $s3 = "000(){return \"OUx\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"NB" ascii
    $s4 = "GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TRc\";})(),(functi" ascii
    $s5 = "n \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s6 = ",(function f000(){return \"Vu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}