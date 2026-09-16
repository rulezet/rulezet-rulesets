rule TTP_XOR_QUAD_CurrentVersionRun_7c6c {
  strings:
    $key_7c6c = { 2f 03 [2] 0b 0d [2] 20 21 [2] 0e 03 [2] 1a 18 [2] 15 02 [2] 0b 1f [2] 09 1e [2] 12 18 [2] 0e 1f [2] 12 30 }

  condition:
    any of them
}