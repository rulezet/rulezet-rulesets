rule TTP_XOR_QUAD_CurrentVersionRun_7c1c {
  strings:
    $key_7c1c = { 2f 73 [2] 0b 7d [2] 20 51 [2] 0e 73 [2] 1a 68 [2] 15 72 [2] 0b 6f [2] 09 6e [2] 12 68 [2] 0e 6f [2] 12 40 }

  condition:
    any of them
}