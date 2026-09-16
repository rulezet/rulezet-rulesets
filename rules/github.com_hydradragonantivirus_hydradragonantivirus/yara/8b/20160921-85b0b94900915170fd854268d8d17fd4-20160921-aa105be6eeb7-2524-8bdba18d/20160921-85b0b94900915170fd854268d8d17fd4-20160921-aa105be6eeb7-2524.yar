rule _20160921_85b0b94900915170fd854268d8d17fd4_20160921_aa105be6eeb7_2524 {
  meta:
    description = "datamaliciousorder - from files 20160921_85b0b94900915170fd854268d8d17fd4.js, 20160921_aa105be6eeb7f536b3fae098f4cc14ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02801a1fe1d3c30ef8c10eab40eabc26c88f8bc28e76e3aecbbb89d0981b21af"
    hash2       = "df7bae330cc77ba04437c13d3843c951b5c3db558d70c922c4f339dfdc29abbd"

  strings:
    $s1 = "),(function f000(){return \"Oe\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Do\";})(),(function f000(){" ascii
    $s2 = "{return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(" ascii
    $s3 = "0(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Oe\";" ascii
    $s4 = "urn \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(f" ascii
    $s5 = "ction f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Ml\";})(),(function f000(){return" ascii
    $s6 = " f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Z" ascii
    $s7 = "tion f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return" ascii
    $s8 = "ion f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Do\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}