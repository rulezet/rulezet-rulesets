rule TTP_XOR_QUAD_CurrentVersionRun_7f7d {
  strings:
    $key_7f7d = { 2c 12 [2] 08 1c [2] 23 30 [2] 0d 12 [2] 19 09 [2] 16 13 [2] 08 0e [2] 0a 0f [2] 11 09 [2] 0d 0e [2] 11 21 }

  condition:
    any of them
}