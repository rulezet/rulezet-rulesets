rule TTP_XOR_QUAD_CurrentVersionRun_4201 {
  strings:
    $key_4201 = { 11 6e [2] 35 60 [2] 1e 4c [2] 30 6e [2] 24 75 [2] 2b 6f [2] 35 72 [2] 37 73 [2] 2c 75 [2] 30 72 [2] 2c 5d }

  condition:
    any of them
}