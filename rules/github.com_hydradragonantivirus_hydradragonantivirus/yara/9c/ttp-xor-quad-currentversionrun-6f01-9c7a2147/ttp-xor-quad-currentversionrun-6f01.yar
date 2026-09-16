rule TTP_XOR_QUAD_CurrentVersionRun_6f01 {
  strings:
    $key_6f01 = { 3c 6e [2] 18 60 [2] 33 4c [2] 1d 6e [2] 09 75 [2] 06 6f [2] 18 72 [2] 1a 73 [2] 01 75 [2] 1d 72 [2] 01 5d }

  condition:
    any of them
}