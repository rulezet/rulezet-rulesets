rule TTP_XOR_QUAD_CurrentVersionRun_0036 {
  strings:
    $key_0036 = { 53 59 [2] 77 57 [2] 5c 7b [2] 72 59 [2] 66 42 [2] 69 58 [2] 77 45 [2] 75 44 [2] 6e 42 [2] 72 45 [2] 6e 6a }

  condition:
    any of them
}