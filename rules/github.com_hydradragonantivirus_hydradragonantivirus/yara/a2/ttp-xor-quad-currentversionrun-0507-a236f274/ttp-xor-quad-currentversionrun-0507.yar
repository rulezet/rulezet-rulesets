rule TTP_XOR_QUAD_CurrentVersionRun_0507 {
  strings:
    $key_0507 = { 56 68 [2] 72 66 [2] 59 4a [2] 77 68 [2] 63 73 [2] 6c 69 [2] 72 74 [2] 70 75 [2] 6b 73 [2] 77 74 [2] 6b 5b }

  condition:
    any of them
}