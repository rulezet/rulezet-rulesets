rule TTP_XOR_QUAD_CurrentVersionRun_647c {
  strings:
    $key_647c = { 37 13 [2] 13 1d [2] 38 31 [2] 16 13 [2] 02 08 [2] 0d 12 [2] 13 0f [2] 11 0e [2] 0a 08 [2] 16 0f [2] 0a 20 }

  condition:
    any of them
}