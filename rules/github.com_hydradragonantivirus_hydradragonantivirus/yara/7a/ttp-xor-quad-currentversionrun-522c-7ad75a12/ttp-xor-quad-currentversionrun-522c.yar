rule TTP_XOR_QUAD_CurrentVersionRun_522c {
  strings:
    $key_522c = { 01 43 [2] 25 4d [2] 0e 61 [2] 20 43 [2] 34 58 [2] 3b 42 [2] 25 5f [2] 27 5e [2] 3c 58 [2] 20 5f [2] 3c 70 }

  condition:
    any of them
}