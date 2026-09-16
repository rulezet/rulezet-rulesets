rule TTP_XOR_QUAD_CurrentVersionRun_5216 {
  strings:
    $key_5216 = { 01 79 [2] 25 77 [2] 0e 5b [2] 20 79 [2] 34 62 [2] 3b 78 [2] 25 65 [2] 27 64 [2] 3c 62 [2] 20 65 [2] 3c 4a }

  condition:
    any of them
}