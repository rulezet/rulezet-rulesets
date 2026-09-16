rule TTP_XOR_QUAD_CurrentVersionRun_7b50 {
  strings:
    $key_7b50 = { 28 3f [2] 0c 31 [2] 27 1d [2] 09 3f [2] 1d 24 [2] 12 3e [2] 0c 23 [2] 0e 22 [2] 15 24 [2] 09 23 [2] 15 0c }

  condition:
    any of them
}