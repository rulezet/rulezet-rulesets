rule TTP_XOR_QUAD_CurrentVersionRun_00d1 {
  strings:
    $key_00d1 = { 53 be [2] 77 b0 [2] 5c 9c [2] 72 be [2] 66 a5 [2] 69 bf [2] 77 a2 [2] 75 a3 [2] 6e a5 [2] 72 a2 [2] 6e 8d }

  condition:
    any of them
}