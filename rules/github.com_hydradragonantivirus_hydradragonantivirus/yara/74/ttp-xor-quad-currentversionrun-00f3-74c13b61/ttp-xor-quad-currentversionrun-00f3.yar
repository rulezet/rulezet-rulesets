rule TTP_XOR_QUAD_CurrentVersionRun_00f3 {
  strings:
    $key_00f3 = { 53 9c [2] 77 92 [2] 5c be [2] 72 9c [2] 66 87 [2] 69 9d [2] 77 80 [2] 75 81 [2] 6e 87 [2] 72 80 [2] 6e af }

  condition:
    any of them
}