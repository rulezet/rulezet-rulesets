rule TTP_XOR_QUAD_CurrentVersionRun_6216 {
  strings:
    $key_6216 = { 31 79 [2] 15 77 [2] 3e 5b [2] 10 79 [2] 04 62 [2] 0b 78 [2] 15 65 [2] 17 64 [2] 0c 62 [2] 10 65 [2] 0c 4a }

  condition:
    any of them
}