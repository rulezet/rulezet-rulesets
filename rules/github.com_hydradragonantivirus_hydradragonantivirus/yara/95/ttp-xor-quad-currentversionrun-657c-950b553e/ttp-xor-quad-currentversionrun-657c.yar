rule TTP_XOR_QUAD_CurrentVersionRun_657c {
  strings:
    $key_657c = { 36 13 [2] 12 1d [2] 39 31 [2] 17 13 [2] 03 08 [2] 0c 12 [2] 12 0f [2] 10 0e [2] 0b 08 [2] 17 0f [2] 0b 20 }

  condition:
    any of them
}