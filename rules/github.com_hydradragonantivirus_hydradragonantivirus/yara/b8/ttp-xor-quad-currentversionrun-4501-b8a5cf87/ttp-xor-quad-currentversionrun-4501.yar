rule TTP_XOR_QUAD_CurrentVersionRun_4501 {
  strings:
    $key_4501 = { 16 6e [2] 32 60 [2] 19 4c [2] 37 6e [2] 23 75 [2] 2c 6f [2] 32 72 [2] 30 73 [2] 2b 75 [2] 37 72 [2] 2b 5d }

  condition:
    any of them
}