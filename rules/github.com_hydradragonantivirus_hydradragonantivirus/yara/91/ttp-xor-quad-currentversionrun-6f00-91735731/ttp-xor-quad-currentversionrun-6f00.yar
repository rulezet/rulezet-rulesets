rule TTP_XOR_QUAD_CurrentVersionRun_6f00 {
  strings:
    $key_6f00 = { 3c 6f [2] 18 61 [2] 33 4d [2] 1d 6f [2] 09 74 [2] 06 6e [2] 18 73 [2] 1a 72 [2] 01 74 [2] 1d 73 [2] 01 5c }

  condition:
    any of them
}