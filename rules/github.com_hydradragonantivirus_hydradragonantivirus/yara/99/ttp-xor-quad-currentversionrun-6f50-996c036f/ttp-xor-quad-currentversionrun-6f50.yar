rule TTP_XOR_QUAD_CurrentVersionRun_6f50 {
  strings:
    $key_6f50 = { 3c 3f [2] 18 31 [2] 33 1d [2] 1d 3f [2] 09 24 [2] 06 3e [2] 18 23 [2] 1a 22 [2] 01 24 [2] 1d 23 [2] 01 0c }

  condition:
    any of them
}