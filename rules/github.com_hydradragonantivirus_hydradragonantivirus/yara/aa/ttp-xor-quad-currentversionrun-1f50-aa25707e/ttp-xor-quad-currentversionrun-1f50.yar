rule TTP_XOR_QUAD_CurrentVersionRun_1f50 {
  strings:
    $key_1f50 = { 4c 3f [2] 68 31 [2] 43 1d [2] 6d 3f [2] 79 24 [2] 76 3e [2] 68 23 [2] 6a 22 [2] 71 24 [2] 6d 23 [2] 71 0c }

  condition:
    any of them
}