rule TTP_XOR_QUAD_CurrentVersionRun_2b0b {
  strings:
    $key_2b0b = { 78 64 [2] 5c 6a [2] 77 46 [2] 59 64 [2] 4d 7f [2] 42 65 [2] 5c 78 [2] 5e 79 [2] 45 7f [2] 59 78 [2] 45 57 }

  condition:
    any of them
}