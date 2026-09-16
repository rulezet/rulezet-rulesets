rule TTP_XOR_QUAD_CurrentVersionRun_f187 {
  strings:
    $key_f187 = { a2 e8 [2] 86 e6 [2] ad ca [2] 83 e8 [2] 97 f3 [2] 98 e9 [2] 86 f4 [2] 84 f5 [2] 9f f3 [2] 83 f4 [2] 9f db }

  condition:
    any of them
}