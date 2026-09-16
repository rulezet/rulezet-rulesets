rule TTP_XOR_QUAD_CurrentVersionRun_e887 {
  strings:
    $key_e887 = { bb e8 [2] 9f e6 [2] b4 ca [2] 9a e8 [2] 8e f3 [2] 81 e9 [2] 9f f4 [2] 9d f5 [2] 86 f3 [2] 9a f4 [2] 86 db }

  condition:
    any of them
}