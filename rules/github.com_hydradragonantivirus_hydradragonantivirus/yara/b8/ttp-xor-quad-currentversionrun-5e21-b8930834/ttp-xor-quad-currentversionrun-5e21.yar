rule TTP_XOR_QUAD_CurrentVersionRun_5e21 {
  strings:
    $key_5e21 = { 0d 4e [2] 29 40 [2] 02 6c [2] 2c 4e [2] 38 55 [2] 37 4f [2] 29 52 [2] 2b 53 [2] 30 55 [2] 2c 52 [2] 30 7d }

  condition:
    any of them
}