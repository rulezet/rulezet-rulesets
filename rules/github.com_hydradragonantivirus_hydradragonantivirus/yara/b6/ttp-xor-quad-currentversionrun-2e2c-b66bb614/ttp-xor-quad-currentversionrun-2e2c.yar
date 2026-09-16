rule TTP_XOR_QUAD_CurrentVersionRun_2e2c {
  strings:
    $key_2e2c = { 7d 43 [2] 59 4d [2] 72 61 [2] 5c 43 [2] 48 58 [2] 47 42 [2] 59 5f [2] 5b 5e [2] 40 58 [2] 5c 5f [2] 40 70 }

  condition:
    any of them
}