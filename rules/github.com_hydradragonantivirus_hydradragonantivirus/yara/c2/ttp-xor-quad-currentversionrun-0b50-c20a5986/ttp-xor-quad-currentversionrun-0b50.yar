rule TTP_XOR_QUAD_CurrentVersionRun_0b50 {
  strings:
    $key_0b50 = { 58 3f [2] 7c 31 [2] 57 1d [2] 79 3f [2] 6d 24 [2] 62 3e [2] 7c 23 [2] 7e 22 [2] 65 24 [2] 79 23 [2] 65 0c }

  condition:
    any of them
}