rule TTP_XOR_QUAD_CurrentVersionRun_c486 {
  strings:
    $key_c486 = { 97 e9 [2] b3 e7 [2] 98 cb [2] b6 e9 [2] a2 f2 [2] ad e8 [2] b3 f5 [2] b1 f4 [2] aa f2 [2] b6 f5 [2] aa da }

  condition:
    any of them
}