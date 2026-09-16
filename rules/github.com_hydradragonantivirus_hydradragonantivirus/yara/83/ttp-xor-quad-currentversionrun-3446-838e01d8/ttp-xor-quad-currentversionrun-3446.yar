rule TTP_XOR_QUAD_CurrentVersionRun_3446 {
  strings:
    $key_3446 = { 67 29 [2] 43 27 [2] 68 0b [2] 46 29 [2] 52 32 [2] 5d 28 [2] 43 35 [2] 41 34 [2] 5a 32 [2] 46 35 [2] 5a 1a }

  condition:
    any of them
}