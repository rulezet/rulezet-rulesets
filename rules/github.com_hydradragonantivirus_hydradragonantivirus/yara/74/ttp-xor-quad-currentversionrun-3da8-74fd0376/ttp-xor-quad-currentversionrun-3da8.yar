rule TTP_XOR_QUAD_CurrentVersionRun_3da8 {
  strings:
    $key_3da8 = { 6e c7 [2] 4a c9 [2] 61 e5 [2] 4f c7 [2] 5b dc [2] 54 c6 [2] 4a db [2] 48 da [2] 53 dc [2] 4f db [2] 53 f4 }

  condition:
    any of them
}