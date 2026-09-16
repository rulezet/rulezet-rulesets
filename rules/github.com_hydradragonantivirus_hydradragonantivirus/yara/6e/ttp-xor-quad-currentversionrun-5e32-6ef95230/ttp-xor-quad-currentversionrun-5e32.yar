rule TTP_XOR_QUAD_CurrentVersionRun_5e32 {
  strings:
    $key_5e32 = { 0d 5d [2] 29 53 [2] 02 7f [2] 2c 5d [2] 38 46 [2] 37 5c [2] 29 41 [2] 2b 40 [2] 30 46 [2] 2c 41 [2] 30 6e }

  condition:
    any of them
}