rule TTP_XOR_QUAD_CurrentVersionRun_6f60 {
  strings:
    $key_6f60 = { 3c 0f [2] 18 01 [2] 33 2d [2] 1d 0f [2] 09 14 [2] 06 0e [2] 18 13 [2] 1a 12 [2] 01 14 [2] 1d 13 [2] 01 3c }

  condition:
    any of them
}