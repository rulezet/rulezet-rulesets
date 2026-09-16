rule TTP_XOR_QUAD_CurrentVersionRun_5e0c {
  strings:
    $key_5e0c = { 0d 63 [2] 29 6d [2] 02 41 [2] 2c 63 [2] 38 78 [2] 37 62 [2] 29 7f [2] 2b 7e [2] 30 78 [2] 2c 7f [2] 30 50 }

  condition:
    any of them
}