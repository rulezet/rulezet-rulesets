rule TTP_XOR_QUAD_CurrentVersionRun_6f7d {
  strings:
    $key_6f7d = { 3c 12 [2] 18 1c [2] 33 30 [2] 1d 12 [2] 09 09 [2] 06 13 [2] 18 0e [2] 1a 0f [2] 01 09 [2] 1d 0e [2] 01 21 }

  condition:
    any of them
}