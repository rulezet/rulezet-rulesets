rule TTP_XOR_QUAD_CurrentVersionRun_1a7d {
  strings:
    $key_1a7d = { 49 12 [2] 6d 1c [2] 46 30 [2] 68 12 [2] 7c 09 [2] 73 13 [2] 6d 0e [2] 6f 0f [2] 74 09 [2] 68 0e [2] 74 21 }

  condition:
    any of them
}