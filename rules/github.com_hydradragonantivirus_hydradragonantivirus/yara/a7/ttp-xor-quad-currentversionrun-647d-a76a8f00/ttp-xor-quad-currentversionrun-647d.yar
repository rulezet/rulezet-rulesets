rule TTP_XOR_QUAD_CurrentVersionRun_647d {
  strings:
    $key_647d = { 37 12 [2] 13 1c [2] 38 30 [2] 16 12 [2] 02 09 [2] 0d 13 [2] 13 0e [2] 11 0f [2] 0a 09 [2] 16 0e [2] 0a 21 }

  condition:
    any of them
}