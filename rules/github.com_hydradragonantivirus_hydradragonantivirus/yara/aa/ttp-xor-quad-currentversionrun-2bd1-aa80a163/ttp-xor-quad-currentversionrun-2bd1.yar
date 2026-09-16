rule TTP_XOR_QUAD_CurrentVersionRun_2bd1 {
  strings:
    $key_2bd1 = { 78 be [2] 5c b0 [2] 77 9c [2] 59 be [2] 4d a5 [2] 42 bf [2] 5c a2 [2] 5e a3 [2] 45 a5 [2] 59 a2 [2] 45 8d }

  condition:
    any of them
}