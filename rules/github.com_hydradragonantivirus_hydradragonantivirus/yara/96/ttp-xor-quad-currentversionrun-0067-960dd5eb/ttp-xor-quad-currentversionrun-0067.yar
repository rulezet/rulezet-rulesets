rule TTP_XOR_QUAD_CurrentVersionRun_0067 {
  strings:
    $key_0067 = { 53 08 [2] 77 06 [2] 5c 2a [2] 72 08 [2] 66 13 [2] 69 09 [2] 77 14 [2] 75 15 [2] 6e 13 [2] 72 14 [2] 6e 3b }

  condition:
    any of them
}