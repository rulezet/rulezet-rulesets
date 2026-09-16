rule TTP_XOR_QUAD_CurrentVersionRun_2c10 {
  strings:
    $key_2c10 = { 7f 7f [2] 5b 71 [2] 70 5d [2] 5e 7f [2] 4a 64 [2] 45 7e [2] 5b 63 [2] 59 62 [2] 42 64 [2] 5e 63 [2] 42 4c }

  condition:
    any of them
}