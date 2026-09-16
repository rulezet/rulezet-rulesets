rule TTP_XOR_QUAD_CurrentVersionRun_efc6 {
  strings:
    $key_efc6 = { bc a9 [2] 98 a7 [2] b3 8b [2] 9d a9 [2] 89 b2 [2] 86 a8 [2] 98 b5 [2] 9a b4 [2] 81 b2 [2] 9d b5 [2] 81 9a }

  condition:
    any of them
}