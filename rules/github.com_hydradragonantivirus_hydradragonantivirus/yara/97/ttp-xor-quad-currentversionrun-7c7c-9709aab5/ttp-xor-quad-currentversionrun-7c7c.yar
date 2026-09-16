rule TTP_XOR_QUAD_CurrentVersionRun_7c7c {
  strings:
    $key_7c7c = { 2f 13 [2] 0b 1d [2] 20 31 [2] 0e 13 [2] 1a 08 [2] 15 12 [2] 0b 0f [2] 09 0e [2] 12 08 [2] 0e 0f [2] 12 20 }

  condition:
    any of them
}