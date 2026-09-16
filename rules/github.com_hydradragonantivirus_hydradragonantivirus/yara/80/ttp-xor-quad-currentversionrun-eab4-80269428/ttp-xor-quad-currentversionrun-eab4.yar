rule TTP_XOR_QUAD_CurrentVersionRun_eab4 {
  strings:
    $key_eab4 = { b9 db [2] 9d d5 [2] b6 f9 [2] 98 db [2] 8c c0 [2] 83 da [2] 9d c7 [2] 9f c6 [2] 84 c0 [2] 98 c7 [2] 84 e8 }

  condition:
    any of them
}