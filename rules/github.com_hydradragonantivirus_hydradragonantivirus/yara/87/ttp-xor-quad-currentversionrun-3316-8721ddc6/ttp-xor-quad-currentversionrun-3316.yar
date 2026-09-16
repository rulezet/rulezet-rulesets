rule TTP_XOR_QUAD_CurrentVersionRun_3316 {
  strings:
    $key_3316 = { 60 79 [2] 44 77 [2] 6f 5b [2] 41 79 [2] 55 62 [2] 5a 78 [2] 44 65 [2] 46 64 [2] 5d 62 [2] 41 65 [2] 5d 4a }

  condition:
    any of them
}