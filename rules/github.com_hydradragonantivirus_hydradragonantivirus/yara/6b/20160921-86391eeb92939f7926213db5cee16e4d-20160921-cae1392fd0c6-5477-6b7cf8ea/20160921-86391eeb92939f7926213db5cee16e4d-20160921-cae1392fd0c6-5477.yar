rule _20160921_86391eeb92939f7926213db5cee16e4d_20160921_cae1392fd0c6_5477 {
  meta:
    description = "datamaliciousorder - from files 20160921_86391eeb92939f7926213db5cee16e4d.js, 20160921_cae1392fd0c6da8c370b46e3e8040401.js, 20160921_e83251070761df6a7fe56a790f4a7a43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1238f360c84929f303678fcd3899297cac43bef18dc5a731b7a6272fde7fe4e6"
    hash2       = "f67c8d099609c97880a9ea12beb3c83faaf2411bf12032595ad5baa45d985a04"
    hash3       = "0ca0db55a551923b328ba28035ed857a5c51dfd4c6e1060bd34ab4bc3d27b75f"

  strings:
    $s1 = "{return \"BIj\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})()" ascii
    $s2 = ")(),(function f000(){return \"OUx\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000" ascii
    $s3 = "),(function f000(){return \"Lo\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000()" ascii
    $s4 = "k\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s5 = "ction f000(){return \"Sj0\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}