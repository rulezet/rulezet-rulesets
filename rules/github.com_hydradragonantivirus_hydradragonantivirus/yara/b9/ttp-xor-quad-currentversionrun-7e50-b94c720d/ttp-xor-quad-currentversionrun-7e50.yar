rule TTP_XOR_QUAD_CurrentVersionRun_7e50 {
  strings:
    $key_7e50 = { 2d 3f [2] 09 31 [2] 22 1d [2] 0c 3f [2] 18 24 [2] 17 3e [2] 09 23 [2] 0b 22 [2] 10 24 [2] 0c 23 [2] 10 0c }

  condition:
    any of them
}