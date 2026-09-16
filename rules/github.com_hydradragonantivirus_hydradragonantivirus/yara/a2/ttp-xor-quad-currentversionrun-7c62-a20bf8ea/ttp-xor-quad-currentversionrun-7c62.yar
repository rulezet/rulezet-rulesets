rule TTP_XOR_QUAD_CurrentVersionRun_7c62 {
  strings:
    $key_7c62 = { 2f 0d [2] 0b 03 [2] 20 2f [2] 0e 0d [2] 1a 16 [2] 15 0c [2] 0b 11 [2] 09 10 [2] 12 16 [2] 0e 11 [2] 12 3e }

  condition:
    any of them
}