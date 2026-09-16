rule TTP_XOR_QUAD_CurrentVersionRun_004d {
  strings:
    $key_004d = { 53 22 [2] 77 2c [2] 5c 00 [2] 72 22 [2] 66 39 [2] 69 23 [2] 77 3e [2] 75 3f [2] 6e 39 [2] 72 3e [2] 6e 11 }

  condition:
    any of them
}