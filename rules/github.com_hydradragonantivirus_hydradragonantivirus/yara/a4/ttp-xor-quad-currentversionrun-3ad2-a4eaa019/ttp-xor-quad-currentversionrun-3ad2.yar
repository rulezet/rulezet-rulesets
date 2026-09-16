rule TTP_XOR_QUAD_CurrentVersionRun_3ad2 {
  strings:
    $key_3ad2 = { 69 bd [2] 4d b3 [2] 66 9f [2] 48 bd [2] 5c a6 [2] 53 bc [2] 4d a1 [2] 4f a0 [2] 54 a6 [2] 48 a1 [2] 54 8e }

  condition:
    any of them
}