rule TTP_XOR_QUAD_CurrentVersionRun_451d {
  strings:
    $key_451d = { 16 72 [2] 32 7c [2] 19 50 [2] 37 72 [2] 23 69 [2] 2c 73 [2] 32 6e [2] 30 6f [2] 2b 69 [2] 37 6e [2] 2b 41 }

  condition:
    any of them
}