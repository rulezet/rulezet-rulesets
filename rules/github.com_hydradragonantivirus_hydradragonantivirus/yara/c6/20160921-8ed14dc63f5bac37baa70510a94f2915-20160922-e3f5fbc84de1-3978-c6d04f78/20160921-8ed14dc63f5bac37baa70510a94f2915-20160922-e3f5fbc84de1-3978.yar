rule _20160921_8ed14dc63f5bac37baa70510a94f2915_20160922_e3f5fbc84de1_3978 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ed14dc63f5bac37baa70510a94f2915.js, 20160922_e3f5fbc84de17ad7f507fc3f34b8151f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e01d4cea60f1c16b2fc3a28a98b5ad4d421b0c4e8e5f757805e98a1436a9fadd"
    hash2       = "f0d0a0daceb43d9d9a2f5d51fcc03568ed541f8699acb8b17ce2131c29f14abf"

  strings:
    $s1 = "f000(){return \"UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"I" ascii
    $s2 = "),(function f000(){return \"Go\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(function f000(){" ascii
    $s3 = "\"Wb\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(func" ascii
    $s4 = "(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Go\";})(),(function f000(){r" ascii
    $s5 = "0(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"XTn\";" ascii
    $s6 = "000(){return \"Uo\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}