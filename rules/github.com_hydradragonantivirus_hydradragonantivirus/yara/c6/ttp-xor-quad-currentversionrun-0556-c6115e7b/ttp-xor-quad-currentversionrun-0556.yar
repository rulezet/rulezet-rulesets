rule TTP_XOR_QUAD_CurrentVersionRun_0556 {
  strings:
    $key_0556 = { 56 39 [2] 72 37 [2] 59 1b [2] 77 39 [2] 63 22 [2] 6c 38 [2] 72 25 [2] 70 24 [2] 6b 22 [2] 77 25 [2] 6b 0a }

  condition:
    any of them
}