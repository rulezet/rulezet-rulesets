rule TTP_XOR_QUAD_CurrentVersionRun_3416 {
  strings:
    $key_3416 = { 67 79 [2] 43 77 [2] 68 5b [2] 46 79 [2] 52 62 [2] 5d 78 [2] 43 65 [2] 41 64 [2] 5a 62 [2] 46 65 [2] 5a 4a }

  condition:
    any of them
}