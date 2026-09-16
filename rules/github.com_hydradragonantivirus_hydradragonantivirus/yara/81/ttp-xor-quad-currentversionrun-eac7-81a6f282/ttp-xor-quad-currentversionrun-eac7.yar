rule TTP_XOR_QUAD_CurrentVersionRun_eac7 {
  strings:
    $key_eac7 = { b9 a8 [2] 9d a6 [2] b6 8a [2] 98 a8 [2] 8c b3 [2] 83 a9 [2] 9d b4 [2] 9f b5 [2] 84 b3 [2] 98 b4 [2] 84 9b }

  condition:
    any of them
}