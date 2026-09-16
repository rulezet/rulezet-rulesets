rule TTP_XOR_QUAD_CurrentVersionRun_6906 {
  strings:
    $key_6906 = { 3a 69 [2] 1e 67 [2] 35 4b [2] 1b 69 [2] 0f 72 [2] 00 68 [2] 1e 75 [2] 1c 74 [2] 07 72 [2] 1b 75 [2] 07 5a }

  condition:
    any of them
}