rule TTP_XOR_QUAD_CurrentVersionRun_4800 {
  strings:
    $key_4800 = { 1b 6f [2] 3f 61 [2] 14 4d [2] 3a 6f [2] 2e 74 [2] 21 6e [2] 3f 73 [2] 3d 72 [2] 26 74 [2] 3a 73 [2] 26 5c }

  condition:
    any of them
}