rule TTP_XOR_QUAD_CurrentVersionRun_eab5 {
  strings:
    $key_eab5 = { b9 da [2] 9d d4 [2] b6 f8 [2] 98 da [2] 8c c1 [2] 83 db [2] 9d c6 [2] 9f c7 [2] 84 c1 [2] 98 c6 [2] 84 e9 }

  condition:
    any of them
}