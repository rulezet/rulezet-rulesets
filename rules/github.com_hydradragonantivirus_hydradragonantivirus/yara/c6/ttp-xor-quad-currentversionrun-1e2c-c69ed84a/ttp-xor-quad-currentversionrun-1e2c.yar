rule TTP_XOR_QUAD_CurrentVersionRun_1e2c {
  strings:
    $key_1e2c = { 4d 43 [2] 69 4d [2] 42 61 [2] 6c 43 [2] 78 58 [2] 77 42 [2] 69 5f [2] 6b 5e [2] 70 58 [2] 6c 5f [2] 70 70 }

  condition:
    any of them
}