rule TTP_XOR_QUAD_CurrentVersionRun_2c3c {
  strings:
    $key_2c3c = { 7f 53 [2] 5b 5d [2] 70 71 [2] 5e 53 [2] 4a 48 [2] 45 52 [2] 5b 4f [2] 59 4e [2] 42 48 [2] 5e 4f [2] 42 60 }

  condition:
    any of them
}