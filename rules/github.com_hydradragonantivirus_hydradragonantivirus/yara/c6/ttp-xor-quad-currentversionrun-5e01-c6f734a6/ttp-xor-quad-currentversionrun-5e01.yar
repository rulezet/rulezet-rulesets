rule TTP_XOR_QUAD_CurrentVersionRun_5e01 {
  strings:
    $key_5e01 = { 0d 6e [2] 29 60 [2] 02 4c [2] 2c 6e [2] 38 75 [2] 37 6f [2] 29 72 [2] 2b 73 [2] 30 75 [2] 2c 72 [2] 30 5d }

  condition:
    any of them
}