rule TTP_XOR_QUAD_CurrentVersionRun_701d {
  strings:
    $key_701d = { 23 72 [2] 07 7c [2] 2c 50 [2] 02 72 [2] 16 69 [2] 19 73 [2] 07 6e [2] 05 6f [2] 1e 69 [2] 02 6e [2] 1e 41 }

  condition:
    any of them
}