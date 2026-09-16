rule TTP_XOR_QUAD_CurrentVersionRun_602c {
  strings:
    $key_602c = { 33 43 [2] 17 4d [2] 3c 61 [2] 12 43 [2] 06 58 [2] 09 42 [2] 17 5f [2] 15 5e [2] 0e 58 [2] 12 5f [2] 0e 70 }

  condition:
    any of them
}