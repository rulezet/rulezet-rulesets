rule TTP_XOR_QUAD_CurrentVersionRun_0006 {
  strings:
    $key_0006 = { 53 69 [2] 77 67 [2] 5c 4b [2] 72 69 [2] 66 72 [2] 69 68 [2] 77 75 [2] 75 74 [2] 6e 72 [2] 72 75 [2] 6e 5a }

  condition:
    any of them
}