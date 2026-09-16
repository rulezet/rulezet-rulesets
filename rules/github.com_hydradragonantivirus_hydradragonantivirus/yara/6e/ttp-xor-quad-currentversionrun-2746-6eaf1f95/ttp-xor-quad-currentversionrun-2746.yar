rule TTP_XOR_QUAD_CurrentVersionRun_2746 {
  strings:
    $key_2746 = { 74 29 [2] 50 27 [2] 7b 0b [2] 55 29 [2] 41 32 [2] 4e 28 [2] 50 35 [2] 52 34 [2] 49 32 [2] 55 35 [2] 49 1a }

  condition:
    any of them
}