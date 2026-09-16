rule TTP_XOR_QUAD_CurrentVersionRun_5e10 {
  strings:
    $key_5e10 = { 0d 7f [2] 29 71 [2] 02 5d [2] 2c 7f [2] 38 64 [2] 37 7e [2] 29 63 [2] 2b 62 [2] 30 64 [2] 2c 63 [2] 30 4c }

  condition:
    any of them
}