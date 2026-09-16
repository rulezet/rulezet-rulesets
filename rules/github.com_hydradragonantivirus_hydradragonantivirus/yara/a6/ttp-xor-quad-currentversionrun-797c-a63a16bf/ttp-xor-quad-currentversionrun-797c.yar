rule TTP_XOR_QUAD_CurrentVersionRun_797c {
  strings:
    $key_797c = { 2a 13 [2] 0e 1d [2] 25 31 [2] 0b 13 [2] 1f 08 [2] 10 12 [2] 0e 0f [2] 0c 0e [2] 17 08 [2] 0b 0f [2] 17 20 }

  condition:
    any of them
}