rule TTP_XOR_QUAD_CurrentVersionRun_c39d {
  strings:
    $key_c39d = { 90 f2 [2] b4 fc [2] 9f d0 [2] b1 f2 [2] a5 e9 [2] aa f3 [2] b4 ee [2] b6 ef [2] ad e9 [2] b1 ee [2] ad c1 }

  condition:
    any of them
}