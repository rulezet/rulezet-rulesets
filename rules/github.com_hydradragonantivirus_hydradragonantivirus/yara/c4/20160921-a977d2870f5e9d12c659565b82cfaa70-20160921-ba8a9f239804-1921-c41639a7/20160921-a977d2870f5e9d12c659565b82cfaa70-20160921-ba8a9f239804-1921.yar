rule _20160921_a977d2870f5e9d12c659565b82cfaa70_20160921_ba8a9f239804_1921 {
  meta:
    description = "datamaliciousorder - from files 20160921_a977d2870f5e9d12c659565b82cfaa70.js, 20160921_ba8a9f239804499b5d1d2a06a862c1ca.js, 20160921_c6572694e5172932491036c67fc9ffe4.js, 20160921_ee1327bdf201e62d1f7ae5482cabbd90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53eed08aece7cc2a81b9828098c3d3e70042a4891863f1130086a0661fc12870"
    hash2       = "4ab28724a794acc5764f2e51f93d2b91ef9513b43e4cb9b0d10bad2710c2e6d7"
    hash3       = "e6ae2536ba0486138837b2ae1457fd029e88f0c21975b726f4edd05ba182b08e"
    hash4       = "91500ac726f9d2548dffc99162aeece9863dc7b928106d27a769e6bbf9439f81"

  strings:
    $s1  = "0(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";" ascii
    $s2  = "rn \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s3  = "000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc" ascii
    $s4  = "00(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\"" ascii
    $s5  = "Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s6  = "c\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(function" ascii
    $s7  = "return \"Vu\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})()" ascii
    $s8  = "on f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s9  = "{return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii
    $s10 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}