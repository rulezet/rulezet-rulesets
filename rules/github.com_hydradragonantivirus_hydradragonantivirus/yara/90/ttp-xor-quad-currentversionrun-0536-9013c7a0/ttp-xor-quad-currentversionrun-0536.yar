rule TTP_XOR_QUAD_CurrentVersionRun_0536 {
  strings:
    $key_0536 = { 56 59 [2] 72 57 [2] 59 7b [2] 77 59 [2] 63 42 [2] 6c 58 [2] 72 45 [2] 70 44 [2] 6b 42 [2] 77 45 [2] 6b 6a }

  condition:
    any of them
}