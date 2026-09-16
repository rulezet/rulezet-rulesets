rule TTP_XOR_QUAD_CurrentVersionRun_451a {
  strings:
    $key_451a = { 16 75 [2] 32 7b [2] 19 57 [2] 37 75 [2] 23 6e [2] 2c 74 [2] 32 69 [2] 30 68 [2] 2b 6e [2] 37 69 [2] 2b 46 }

  condition:
    any of them
}