rule TTP_XOR_QUAD_CurrentVersionRun_00f4 {
  strings:
    $key_00f4 = { 53 9b [2] 77 95 [2] 5c b9 [2] 72 9b [2] 66 80 [2] 69 9a [2] 77 87 [2] 75 86 [2] 6e 80 [2] 72 87 [2] 6e a8 }

  condition:
    any of them
}