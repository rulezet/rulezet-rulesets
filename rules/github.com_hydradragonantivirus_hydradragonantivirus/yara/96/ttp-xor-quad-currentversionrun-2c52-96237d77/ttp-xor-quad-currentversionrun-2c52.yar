rule TTP_XOR_QUAD_CurrentVersionRun_2c52 {
  strings:
    $key_2c52 = { 7f 3d [2] 5b 33 [2] 70 1f [2] 5e 3d [2] 4a 26 [2] 45 3c [2] 5b 21 [2] 59 20 [2] 42 26 [2] 5e 21 [2] 42 0e }

  condition:
    any of them
}