rule TTP_XOR_QUAD_CurrentVersionRun_2f7d {
  strings:
    $key_2f7d = { 7c 12 [2] 58 1c [2] 73 30 [2] 5d 12 [2] 49 09 [2] 46 13 [2] 58 0e [2] 5a 0f [2] 41 09 [2] 5d 0e [2] 41 21 }

  condition:
    any of them
}