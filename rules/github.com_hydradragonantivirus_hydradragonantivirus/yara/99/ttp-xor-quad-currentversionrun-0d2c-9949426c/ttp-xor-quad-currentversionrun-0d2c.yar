rule TTP_XOR_QUAD_CurrentVersionRun_0d2c {
  strings:
    $key_0d2c = { 5e 43 [2] 7a 4d [2] 51 61 [2] 7f 43 [2] 6b 58 [2] 64 42 [2] 7a 5f [2] 78 5e [2] 63 58 [2] 7f 5f [2] 63 70 }

  condition:
    any of them
}