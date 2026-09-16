rule TTP_XOR_QUAD_CurrentVersionRun_0ad1 {
  strings:
    $key_0ad1 = { 59 be [2] 7d b0 [2] 56 9c [2] 78 be [2] 6c a5 [2] 63 bf [2] 7d a2 [2] 7f a3 [2] 64 a5 [2] 78 a2 [2] 64 8d }

  condition:
    any of them
}