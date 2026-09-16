rule _20160921_85b0b94900915170fd854268d8d17fd4_20160921_86391eeb9293_5466 {
  meta:
    description = "datamaliciousorder - from files 20160921_85b0b94900915170fd854268d8d17fd4.js, 20160921_86391eeb92939f7926213db5cee16e4d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02801a1fe1d3c30ef8c10eab40eabc26c88f8bc28e76e3aecbbb89d0981b21af"
    hash2       = "1238f360c84929f303678fcd3899297cac43bef18dc5a731b7a6272fde7fe4e6"

  strings:
    $s1 = "unction f000(){return \"Rh\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Br\";})(),(function f000(){retu" ascii
    $s2 = "{return \"TKl\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})()" ascii
    $s3 = "ion f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return " ascii
    $s4 = ")(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Lp\";})(),(function f000(" ascii
    $s5 = "ction f000(){return \"ZIi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}