rule TTP_XOR_QUAD_CurrentVersionRun_1350 {
  strings:
    $key_1350 = { 40 3f [2] 64 31 [2] 4f 1d [2] 61 3f [2] 75 24 [2] 7a 3e [2] 64 23 [2] 66 22 [2] 7d 24 [2] 61 23 [2] 7d 0c }

  condition:
    any of them
}