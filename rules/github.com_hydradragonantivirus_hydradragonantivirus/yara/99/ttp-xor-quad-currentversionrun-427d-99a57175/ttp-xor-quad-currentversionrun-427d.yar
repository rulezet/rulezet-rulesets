rule TTP_XOR_QUAD_CurrentVersionRun_427d {
  strings:
    $key_427d = { 11 12 [2] 35 1c [2] 1e 30 [2] 30 12 [2] 24 09 [2] 2b 13 [2] 35 0e [2] 37 0f [2] 2c 09 [2] 30 0e [2] 2c 21 }

  condition:
    any of them
}