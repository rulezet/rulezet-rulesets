rule TTP_XOR_QUAD_CurrentVersionRun_691a {
  strings:
    $key_691a = { 3a 75 [2] 1e 7b [2] 35 57 [2] 1b 75 [2] 0f 6e [2] 00 74 [2] 1e 69 [2] 1c 68 [2] 07 6e [2] 1b 69 [2] 07 46 }

  condition:
    any of them
}