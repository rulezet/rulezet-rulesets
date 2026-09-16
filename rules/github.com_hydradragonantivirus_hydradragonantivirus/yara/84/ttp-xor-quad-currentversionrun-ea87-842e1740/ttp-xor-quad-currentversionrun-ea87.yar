rule TTP_XOR_QUAD_CurrentVersionRun_ea87 {
  strings:
    $key_ea87 = { b9 e8 [2] 9d e6 [2] b6 ca [2] 98 e8 [2] 8c f3 [2] 83 e9 [2] 9d f4 [2] 9f f5 [2] 84 f3 [2] 98 f4 [2] 84 db }

  condition:
    any of them
}