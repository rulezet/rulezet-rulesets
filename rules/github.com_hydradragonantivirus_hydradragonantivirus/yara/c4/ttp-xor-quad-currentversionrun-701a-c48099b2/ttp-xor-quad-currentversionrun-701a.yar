rule TTP_XOR_QUAD_CurrentVersionRun_701a {
  strings:
    $key_701a = { 23 75 [2] 07 7b [2] 2c 57 [2] 02 75 [2] 16 6e [2] 19 74 [2] 07 69 [2] 05 68 [2] 1e 6e [2] 02 69 [2] 1e 46 }

  condition:
    any of them
}