rule TTP_XOR_QUAD_CurrentVersionRun_6350 {
  strings:
    $key_6350 = { 30 3f [2] 14 31 [2] 3f 1d [2] 11 3f [2] 05 24 [2] 0a 3e [2] 14 23 [2] 16 22 [2] 0d 24 [2] 11 23 [2] 0d 0c }

  condition:
    any of them
}