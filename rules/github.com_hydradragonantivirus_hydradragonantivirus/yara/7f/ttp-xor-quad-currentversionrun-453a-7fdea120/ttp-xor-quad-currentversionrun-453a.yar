rule TTP_XOR_QUAD_CurrentVersionRun_453a {
  strings:
    $key_453a = { 16 55 [2] 32 5b [2] 19 77 [2] 37 55 [2] 23 4e [2] 2c 54 [2] 32 49 [2] 30 48 [2] 2b 4e [2] 37 49 [2] 2b 66 }

  condition:
    any of them
}