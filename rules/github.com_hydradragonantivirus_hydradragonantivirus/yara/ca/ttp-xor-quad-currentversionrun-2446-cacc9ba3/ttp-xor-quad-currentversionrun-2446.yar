rule TTP_XOR_QUAD_CurrentVersionRun_2446 {
  strings:
    $key_2446 = { 77 29 [2] 53 27 [2] 78 0b [2] 56 29 [2] 42 32 [2] 4d 28 [2] 53 35 [2] 51 34 [2] 4a 32 [2] 56 35 [2] 4a 1a }

  condition:
    any of them
}