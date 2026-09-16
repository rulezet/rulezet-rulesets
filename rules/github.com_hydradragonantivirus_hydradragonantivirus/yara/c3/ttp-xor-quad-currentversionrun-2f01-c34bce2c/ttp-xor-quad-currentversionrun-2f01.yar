rule TTP_XOR_QUAD_CurrentVersionRun_2f01 {
  strings:
    $key_2f01 = { 7c 6e [2] 58 60 [2] 73 4c [2] 5d 6e [2] 49 75 [2] 46 6f [2] 58 72 [2] 5a 73 [2] 41 75 [2] 5d 72 [2] 41 5d }

  condition:
    any of them
}