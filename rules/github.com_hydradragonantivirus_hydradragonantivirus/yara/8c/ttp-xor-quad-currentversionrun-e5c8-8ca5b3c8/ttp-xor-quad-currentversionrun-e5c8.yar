rule TTP_XOR_QUAD_CurrentVersionRun_e5c8 {
  strings:
    $key_e5c8 = { b6 a7 [2] 92 a9 [2] b9 85 [2] 97 a7 [2] 83 bc [2] 8c a6 [2] 92 bb [2] 90 ba [2] 8b bc [2] 97 bb [2] 8b 94 }

  condition:
    any of them
}