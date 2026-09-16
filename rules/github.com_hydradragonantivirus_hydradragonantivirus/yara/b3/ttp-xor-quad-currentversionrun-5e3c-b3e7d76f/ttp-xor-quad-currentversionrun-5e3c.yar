rule TTP_XOR_QUAD_CurrentVersionRun_5e3c {
  strings:
    $key_5e3c = { 0d 53 [2] 29 5d [2] 02 71 [2] 2c 53 [2] 38 48 [2] 37 52 [2] 29 4f [2] 2b 4e [2] 30 48 [2] 2c 4f [2] 30 60 }

  condition:
    any of them
}