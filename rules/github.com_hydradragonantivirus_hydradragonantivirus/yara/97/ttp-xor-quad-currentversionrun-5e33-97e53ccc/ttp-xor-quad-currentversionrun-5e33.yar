rule TTP_XOR_QUAD_CurrentVersionRun_5e33 {
  strings:
    $key_5e33 = { 0d 5c [2] 29 52 [2] 02 7e [2] 2c 5c [2] 38 47 [2] 37 5d [2] 29 40 [2] 2b 41 [2] 30 47 [2] 2c 40 [2] 30 6f }

  condition:
    any of them
}