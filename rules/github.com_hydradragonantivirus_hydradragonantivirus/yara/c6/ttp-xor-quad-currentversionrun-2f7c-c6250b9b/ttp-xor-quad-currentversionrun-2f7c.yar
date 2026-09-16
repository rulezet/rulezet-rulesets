rule TTP_XOR_QUAD_CurrentVersionRun_2f7c {
  strings:
    $key_2f7c = { 7c 13 [2] 58 1d [2] 73 31 [2] 5d 13 [2] 49 08 [2] 46 12 [2] 58 0f [2] 5a 0e [2] 41 08 [2] 5d 0f [2] 41 20 }

  condition:
    any of them
}