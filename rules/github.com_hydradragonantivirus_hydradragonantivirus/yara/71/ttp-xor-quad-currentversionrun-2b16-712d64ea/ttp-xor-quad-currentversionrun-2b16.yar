rule TTP_XOR_QUAD_CurrentVersionRun_2b16 {
  strings:
    $key_2b16 = { 78 79 [2] 5c 77 [2] 77 5b [2] 59 79 [2] 4d 62 [2] 42 78 [2] 5c 65 [2] 5e 64 [2] 45 62 [2] 59 65 [2] 45 4a }

  condition:
    any of them
}