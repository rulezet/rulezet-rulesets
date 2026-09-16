rule TTP_XOR_QUAD_CurrentVersionRun_047c {
  strings:
    $key_047c = { 57 13 [2] 73 1d [2] 58 31 [2] 76 13 [2] 62 08 [2] 6d 12 [2] 73 0f [2] 71 0e [2] 6a 08 [2] 76 0f [2] 6a 20 }

  condition:
    any of them
}