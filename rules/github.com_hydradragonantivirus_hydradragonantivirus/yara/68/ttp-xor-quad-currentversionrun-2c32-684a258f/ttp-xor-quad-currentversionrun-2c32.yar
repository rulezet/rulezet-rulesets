rule TTP_XOR_QUAD_CurrentVersionRun_2c32 {
  strings:
    $key_2c32 = { 7f 5d [2] 5b 53 [2] 70 7f [2] 5e 5d [2] 4a 46 [2] 45 5c [2] 5b 41 [2] 59 40 [2] 42 46 [2] 5e 41 [2] 42 6e }

  condition:
    any of them
}