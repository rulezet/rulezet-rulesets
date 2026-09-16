rule TTP_XOR_QUAD_CurrentVersionRun_5400 {
  strings:
    $key_5400 = { 07 6f [2] 23 61 [2] 08 4d [2] 26 6f [2] 32 74 [2] 3d 6e [2] 23 73 [2] 21 72 [2] 3a 74 [2] 26 73 [2] 3a 5c }

  condition:
    any of them
}