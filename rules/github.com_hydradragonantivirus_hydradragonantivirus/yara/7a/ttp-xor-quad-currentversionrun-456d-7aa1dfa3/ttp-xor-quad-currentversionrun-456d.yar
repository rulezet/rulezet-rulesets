rule TTP_XOR_QUAD_CurrentVersionRun_456d {
  strings:
    $key_456d = { 16 02 [2] 32 0c [2] 19 20 [2] 37 02 [2] 23 19 [2] 2c 03 [2] 32 1e [2] 30 1f [2] 2b 19 [2] 37 1e [2] 2b 31 }

  condition:
    any of them
}