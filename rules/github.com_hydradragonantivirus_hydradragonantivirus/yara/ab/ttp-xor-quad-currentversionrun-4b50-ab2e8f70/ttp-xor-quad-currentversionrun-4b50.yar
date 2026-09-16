rule TTP_XOR_QUAD_CurrentVersionRun_4b50 {
  strings:
    $key_4b50 = { 18 3f [2] 3c 31 [2] 17 1d [2] 39 3f [2] 2d 24 [2] 22 3e [2] 3c 23 [2] 3e 22 [2] 25 24 [2] 39 23 [2] 25 0c }

  condition:
    any of them
}