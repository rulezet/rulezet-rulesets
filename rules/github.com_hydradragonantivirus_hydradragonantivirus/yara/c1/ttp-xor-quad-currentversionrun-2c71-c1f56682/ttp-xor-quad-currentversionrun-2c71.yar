rule TTP_XOR_QUAD_CurrentVersionRun_2c71 {
  strings:
    $key_2c71 = { 7f 1e [2] 5b 10 [2] 70 3c [2] 5e 1e [2] 4a 05 [2] 45 1f [2] 5b 02 [2] 59 03 [2] 42 05 [2] 5e 02 [2] 42 2d }

  condition:
    any of them
}