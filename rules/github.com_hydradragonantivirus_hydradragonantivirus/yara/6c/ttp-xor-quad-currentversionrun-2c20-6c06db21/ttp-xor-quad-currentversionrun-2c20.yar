rule TTP_XOR_QUAD_CurrentVersionRun_2c20 {
  strings:
    $key_2c20 = { 7f 4f [2] 5b 41 [2] 70 6d [2] 5e 4f [2] 4a 54 [2] 45 4e [2] 5b 53 [2] 59 52 [2] 42 54 [2] 5e 53 [2] 42 7c }

  condition:
    any of them
}