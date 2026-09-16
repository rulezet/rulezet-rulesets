rule TTP_XOR_QUAD_CurrentVersionRun_00f9 {
  strings:
    $key_00f9 = { 53 96 [2] 77 98 [2] 5c b4 [2] 72 96 [2] 66 8d [2] 69 97 [2] 77 8a [2] 75 8b [2] 6e 8d [2] 72 8a [2] 6e a5 }

  condition:
    any of them
}