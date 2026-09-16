rule TTP_XOR_QUAD_CurrentVersionRun_047d {
  strings:
    $key_047d = { 57 12 [2] 73 1c [2] 58 30 [2] 76 12 [2] 62 09 [2] 6d 13 [2] 73 0e [2] 71 0f [2] 6a 09 [2] 76 0e [2] 6a 21 }

  condition:
    any of them
}