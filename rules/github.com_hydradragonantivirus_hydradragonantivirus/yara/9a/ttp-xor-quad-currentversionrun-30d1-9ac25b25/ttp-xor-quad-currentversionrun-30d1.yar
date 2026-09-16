rule TTP_XOR_QUAD_CurrentVersionRun_30d1 {
  strings:
    $key_30d1 = { 63 be [2] 47 b0 [2] 6c 9c [2] 42 be [2] 56 a5 [2] 59 bf [2] 47 a2 [2] 45 a3 [2] 5e a5 [2] 42 a2 [2] 5e 8d }

  condition:
    any of them
}