rule TTP_XOR_QUAD_CurrentVersionRun_2e16 {
  strings:
    $key_2e16 = { 7d 79 [2] 59 77 [2] 72 5b [2] 5c 79 [2] 48 62 [2] 47 78 [2] 59 65 [2] 5b 64 [2] 40 62 [2] 5c 65 [2] 40 4a }

  condition:
    any of them
}