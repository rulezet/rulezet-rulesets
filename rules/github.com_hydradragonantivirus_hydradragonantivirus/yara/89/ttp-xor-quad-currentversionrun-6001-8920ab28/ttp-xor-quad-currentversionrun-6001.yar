rule TTP_XOR_QUAD_CurrentVersionRun_6001 {
  strings:
    $key_6001 = { 33 6e [2] 17 60 [2] 3c 4c [2] 12 6e [2] 06 75 [2] 09 6f [2] 17 72 [2] 15 73 [2] 0e 75 [2] 12 72 [2] 0e 5d }

  condition:
    any of them
}