rule TTP_XOR_QUAD_CurrentVersionRun_7c01 {
  strings:
    $key_7c01 = { 2f 6e [2] 0b 60 [2] 20 4c [2] 0e 6e [2] 1a 75 [2] 15 6f [2] 0b 72 [2] 09 73 [2] 12 75 [2] 0e 72 [2] 12 5d }

  condition:
    any of them
}