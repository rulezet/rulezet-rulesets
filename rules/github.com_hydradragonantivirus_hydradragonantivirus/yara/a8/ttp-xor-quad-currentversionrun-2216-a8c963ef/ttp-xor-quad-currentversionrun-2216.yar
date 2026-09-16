rule TTP_XOR_QUAD_CurrentVersionRun_2216 {
  strings:
    $key_2216 = { 71 79 [2] 55 77 [2] 7e 5b [2] 50 79 [2] 44 62 [2] 4b 78 [2] 55 65 [2] 57 64 [2] 4c 62 [2] 50 65 [2] 4c 4a }

  condition:
    any of them
}