rule TTP_XOR_QUAD_CurrentVersionRun_3b46 {
  strings:
    $key_3b46 = { 68 29 [2] 4c 27 [2] 67 0b [2] 49 29 [2] 5d 32 [2] 52 28 [2] 4c 35 [2] 4e 34 [2] 55 32 [2] 49 35 [2] 55 1a }

  condition:
    any of them
}