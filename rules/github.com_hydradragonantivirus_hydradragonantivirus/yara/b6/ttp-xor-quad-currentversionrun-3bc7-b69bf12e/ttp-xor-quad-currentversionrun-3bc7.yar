rule TTP_XOR_QUAD_CurrentVersionRun_3bc7 {
  strings:
    $key_3bc7 = { 68 a8 [2] 4c a6 [2] 67 8a [2] 49 a8 [2] 5d b3 [2] 52 a9 [2] 4c b4 [2] 4e b5 [2] 55 b3 [2] 49 b4 [2] 55 9b }

  condition:
    any of them
}