rule TTP_XOR_QUAD_CurrentVersionRun_7cfc {
  strings:
    $key_7cfc = { 2f 93 [2] 0b 9d [2] 20 b1 [2] 0e 93 [2] 1a 88 [2] 15 92 [2] 0b 8f [2] 09 8e [2] 12 88 [2] 0e 8f [2] 12 a0 }

  condition:
    any of them
}