rule TTP_XOR_QUAD_CurrentVersionRun_637c {
  strings:
    $key_637c = { 30 13 [2] 14 1d [2] 3f 31 [2] 11 13 [2] 05 08 [2] 0a 12 [2] 14 0f [2] 16 0e [2] 0d 08 [2] 11 0f [2] 0d 20 }

  condition:
    any of them
}