rule TTP_XOR_QUAD_CurrentVersionRun_0646 {
  strings:
    $key_0646 = { 55 29 [2] 71 27 [2] 5a 0b [2] 74 29 [2] 60 32 [2] 6f 28 [2] 71 35 [2] 73 34 [2] 68 32 [2] 74 35 [2] 68 1a }

  condition:
    any of them
}