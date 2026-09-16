rule TTP_XOR_QUAD_CurrentVersionRun_e5d7 {
  strings:
    $key_e5d7 = { b6 b8 [2] 92 b6 [2] b9 9a [2] 97 b8 [2] 83 a3 [2] 8c b9 [2] 92 a4 [2] 90 a5 [2] 8b a3 [2] 97 a4 [2] 8b 8b }

  condition:
    any of them
}