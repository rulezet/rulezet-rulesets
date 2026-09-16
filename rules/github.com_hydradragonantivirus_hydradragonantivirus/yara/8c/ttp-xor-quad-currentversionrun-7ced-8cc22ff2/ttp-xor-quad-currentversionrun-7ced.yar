rule TTP_XOR_QUAD_CurrentVersionRun_7ced {
  strings:
    $key_7ced = { 2f 82 [2] 0b 8c [2] 20 a0 [2] 0e 82 [2] 1a 99 [2] 15 83 [2] 0b 9e [2] 09 9f [2] 12 99 [2] 0e 9e [2] 12 b1 }

  condition:
    any of them
}