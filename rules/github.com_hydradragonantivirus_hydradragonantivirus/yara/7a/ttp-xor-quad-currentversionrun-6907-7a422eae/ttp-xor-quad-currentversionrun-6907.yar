rule TTP_XOR_QUAD_CurrentVersionRun_6907 {
  strings:
    $key_6907 = { 3a 68 [2] 1e 66 [2] 35 4a [2] 1b 68 [2] 0f 73 [2] 00 69 [2] 1e 74 [2] 1c 75 [2] 07 73 [2] 1b 74 [2] 07 5b }

  condition:
    any of them
}