rule TTP_XOR_QUAD_CurrentVersionRun_441c {
  strings:
    $key_441c = { 17 73 [2] 33 7d [2] 18 51 [2] 36 73 [2] 22 68 [2] 2d 72 [2] 33 6f [2] 31 6e [2] 2a 68 [2] 36 6f [2] 2a 40 }

  condition:
    any of them
}