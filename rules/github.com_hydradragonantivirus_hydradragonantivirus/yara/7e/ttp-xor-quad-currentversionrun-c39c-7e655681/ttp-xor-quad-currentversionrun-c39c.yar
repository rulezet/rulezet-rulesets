rule TTP_XOR_QUAD_CurrentVersionRun_c39c {
  strings:
    $key_c39c = { 90 f3 [2] b4 fd [2] 9f d1 [2] b1 f3 [2] a5 e8 [2] aa f2 [2] b4 ef [2] b6 ee [2] ad e8 [2] b1 ef [2] ad c0 }

  condition:
    any of them
}