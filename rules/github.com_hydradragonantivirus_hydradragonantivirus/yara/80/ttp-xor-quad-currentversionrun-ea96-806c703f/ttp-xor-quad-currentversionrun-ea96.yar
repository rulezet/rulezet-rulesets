rule TTP_XOR_QUAD_CurrentVersionRun_ea96 {
  strings:
    $key_ea96 = { b9 f9 [2] 9d f7 [2] b6 db [2] 98 f9 [2] 8c e2 [2] 83 f8 [2] 9d e5 [2] 9f e4 [2] 84 e2 [2] 98 e5 [2] 84 ca }

  condition:
    any of them
}