rule TTP_XOR_QUAD_CurrentVersionRun_da85 {
  strings:
    $key_da85 = { 89 ea [2] ad e4 [2] 86 c8 [2] a8 ea [2] bc f1 [2] b3 eb [2] ad f6 [2] af f7 [2] b4 f1 [2] a8 f6 [2] b4 d9 }

  condition:
    any of them
}