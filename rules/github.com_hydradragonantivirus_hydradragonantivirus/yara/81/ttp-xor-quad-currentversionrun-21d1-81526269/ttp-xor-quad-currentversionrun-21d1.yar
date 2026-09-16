rule TTP_XOR_QUAD_CurrentVersionRun_21d1 {
  strings:
    $key_21d1 = { 72 be [2] 56 b0 [2] 7d 9c [2] 53 be [2] 47 a5 [2] 48 bf [2] 56 a2 [2] 54 a3 [2] 4f a5 [2] 53 a2 [2] 4f 8d }

  condition:
    any of them
}