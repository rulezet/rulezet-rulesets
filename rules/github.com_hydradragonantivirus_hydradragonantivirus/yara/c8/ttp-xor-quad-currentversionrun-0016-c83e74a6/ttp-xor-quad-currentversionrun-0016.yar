rule TTP_XOR_QUAD_CurrentVersionRun_0016 {
  strings:
    $key_0016 = { 53 79 [2] 77 77 [2] 5c 5b [2] 72 79 [2] 66 62 [2] 69 78 [2] 77 65 [2] 75 64 [2] 6e 62 [2] 72 65 [2] 6e 4a }

  condition:
    any of them
}