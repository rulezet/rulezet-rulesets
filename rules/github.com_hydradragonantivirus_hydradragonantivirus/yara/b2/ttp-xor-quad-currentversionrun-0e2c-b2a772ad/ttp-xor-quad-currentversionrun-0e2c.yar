rule TTP_XOR_QUAD_CurrentVersionRun_0e2c {
  strings:
    $key_0e2c = { 5d 43 [2] 79 4d [2] 52 61 [2] 7c 43 [2] 68 58 [2] 67 42 [2] 79 5f [2] 7b 5e [2] 60 58 [2] 7c 5f [2] 60 70 }

  condition:
    any of them
}