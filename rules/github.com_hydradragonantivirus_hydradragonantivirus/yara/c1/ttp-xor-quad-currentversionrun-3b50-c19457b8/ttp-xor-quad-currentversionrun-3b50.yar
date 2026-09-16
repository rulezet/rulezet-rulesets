rule TTP_XOR_QUAD_CurrentVersionRun_3b50 {
  strings:
    $key_3b50 = { 68 3f [2] 4c 31 [2] 67 1d [2] 49 3f [2] 5d 24 [2] 52 3e [2] 4c 23 [2] 4e 22 [2] 55 24 [2] 49 23 [2] 55 0c }

  condition:
    any of them
}