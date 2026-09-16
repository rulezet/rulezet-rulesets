rule TTP_XOR_QUAD_CurrentVersionRun_3ad6 {
  strings:
    $key_3ad6 = { 69 b9 [2] 4d b7 [2] 66 9b [2] 48 b9 [2] 5c a2 [2] 53 b8 [2] 4d a5 [2] 4f a4 [2] 54 a2 [2] 48 a5 [2] 54 8a }

  condition:
    any of them
}