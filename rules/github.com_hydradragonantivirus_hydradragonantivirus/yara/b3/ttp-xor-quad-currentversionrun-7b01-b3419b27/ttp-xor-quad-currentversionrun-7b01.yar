rule TTP_XOR_QUAD_CurrentVersionRun_7b01 {
  strings:
    $key_7b01 = { 28 6e [2] 0c 60 [2] 27 4c [2] 09 6e [2] 1d 75 [2] 12 6f [2] 0c 72 [2] 0e 73 [2] 15 75 [2] 09 72 [2] 15 5d }

  condition:
    any of them
}