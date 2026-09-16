rule TTP_XOR_QUAD_CurrentVersionRun_441d {
  strings:
    $key_441d = { 17 72 [2] 33 7c [2] 18 50 [2] 36 72 [2] 22 69 [2] 2d 73 [2] 33 6e [2] 31 6f [2] 2a 69 [2] 36 6e [2] 2a 41 }

  condition:
    any of them
}