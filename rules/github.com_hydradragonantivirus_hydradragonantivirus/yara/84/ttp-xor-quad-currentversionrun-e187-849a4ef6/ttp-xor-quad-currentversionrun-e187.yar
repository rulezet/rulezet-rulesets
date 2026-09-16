rule TTP_XOR_QUAD_CurrentVersionRun_e187 {
  strings:
    $key_e187 = { b2 e8 [2] 96 e6 [2] bd ca [2] 93 e8 [2] 87 f3 [2] 88 e9 [2] 96 f4 [2] 94 f5 [2] 8f f3 [2] 93 f4 [2] 8f db }

  condition:
    any of them
}