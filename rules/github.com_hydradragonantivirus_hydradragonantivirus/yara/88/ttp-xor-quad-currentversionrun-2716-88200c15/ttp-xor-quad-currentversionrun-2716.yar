rule TTP_XOR_QUAD_CurrentVersionRun_2716 {
  strings:
    $key_2716 = { 74 79 [2] 50 77 [2] 7b 5b [2] 55 79 [2] 41 62 [2] 4e 78 [2] 50 65 [2] 52 64 [2] 49 62 [2] 55 65 [2] 49 4a }

  condition:
    any of them
}