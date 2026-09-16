rule _20160921_86391eeb92939f7926213db5cee16e4d_20160921_ba8a9f239804_3952 {
  meta:
    description = "datamaliciousorder - from files 20160921_86391eeb92939f7926213db5cee16e4d.js, 20160921_ba8a9f239804499b5d1d2a06a862c1ca.js, 20160921_d7492227e681b1689bfc5442a91a169e.js, 20160921_ee1327bdf201e62d1f7ae5482cabbd90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1238f360c84929f303678fcd3899297cac43bef18dc5a731b7a6272fde7fe4e6"
    hash2       = "4ab28724a794acc5764f2e51f93d2b91ef9513b43e4cb9b0d10bad2710c2e6d7"
    hash3       = "63aa129680edf69c72e8f077be5e8562f041fa0b0c7e63a8a9b219c23749b135"
    hash4       = "91500ac726f9d2548dffc99162aeece9863dc7b928106d27a769e6bbf9439f81"

  strings:
    $s1 = "(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";}" ascii
    $s2 = "ion f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OMd\";})(),(function f000(){return " ascii
    $s3 = "Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function" ascii
    $s4 = "ction f000(){return \"Ug\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s5 = "eturn \"DYx\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KXg\";})(" ascii
    $s6 = "tion f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Uo\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}