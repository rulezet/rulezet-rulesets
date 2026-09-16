rule TTP_XOR_QUAD_CurrentVersionRun_3e50 {
  strings:
    $key_3e50 = { 6d 3f [2] 49 31 [2] 62 1d [2] 4c 3f [2] 58 24 [2] 57 3e [2] 49 23 [2] 4b 22 [2] 50 24 [2] 4c 23 [2] 50 0c }

  condition:
    any of them
}