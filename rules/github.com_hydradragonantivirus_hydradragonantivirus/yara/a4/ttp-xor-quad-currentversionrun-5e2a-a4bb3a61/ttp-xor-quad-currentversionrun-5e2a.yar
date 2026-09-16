rule TTP_XOR_QUAD_CurrentVersionRun_5e2a {
  strings:
    $key_5e2a = { 0d 45 [2] 29 4b [2] 02 67 [2] 2c 45 [2] 38 5e [2] 37 44 [2] 29 59 [2] 2b 58 [2] 30 5e [2] 2c 59 [2] 30 76 }

  condition:
    any of them
}