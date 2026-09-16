rule _20160921_37aa38f76e02afb64903280105ce4597_20160921_3a89132c2088_3630 {
  meta:
    description = "datamaliciousorder - from files 20160921_37aa38f76e02afb64903280105ce4597.js, 20160921_3a89132c20887c3360a3708984b884fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "768a32c669c193375bb8e7adb97cdbb697cd6f4f09fb5dc67bb63e62b7de29cf"
    hash2       = "9687ad9b2ded14e00c5b17393de82acd451266863fb217fc6647e1add112f2fd"

  strings:
    $s1 = ")(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Nv\";})(),(function f000(" ascii
    $s2 = "ion f000(){return \"GGn\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s3 = "Gn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SEo\";})(),(functio" ascii
    $s4 = "eturn \"PTs\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Wb\";})()" ascii
    $s5 = "on f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"SEo\";})(),(function f000(){return " ascii
    $s6 = ",(function f000(){return \"DAp\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Vj\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}