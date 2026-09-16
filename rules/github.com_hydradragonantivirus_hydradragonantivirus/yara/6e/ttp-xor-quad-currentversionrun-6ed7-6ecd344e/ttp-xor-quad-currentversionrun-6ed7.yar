rule TTP_XOR_QUAD_CurrentVersionRun_6ed7 {
  strings:
    $key_6ed7 = { 3d b8 [2] 19 b6 [2] 32 9a [2] 1c b8 [2] 08 a3 [2] 07 b9 [2] 19 a4 [2] 1b a5 [2] 00 a3 [2] 1c a4 [2] 00 8b }

  condition:
    any of them
}