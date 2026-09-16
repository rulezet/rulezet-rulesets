rule TTP_XOR_QUAD_CurrentVersionRun_3ad7 {
  strings:
    $key_3ad7 = { 69 b8 [2] 4d b6 [2] 66 9a [2] 48 b8 [2] 5c a3 [2] 53 b9 [2] 4d a4 [2] 4f a5 [2] 54 a3 [2] 48 a4 [2] 54 8b }

  condition:
    any of them
}