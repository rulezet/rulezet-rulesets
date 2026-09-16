rule TTP_XOR_QUAD_CurrentVersionRun_0068 {
  strings:
    $key_0068 = { 53 07 [2] 77 09 [2] 5c 25 [2] 72 07 [2] 66 1c [2] 69 06 [2] 77 1b [2] 75 1a [2] 6e 1c [2] 72 1b [2] 6e 34 }

  condition:
    any of them
}