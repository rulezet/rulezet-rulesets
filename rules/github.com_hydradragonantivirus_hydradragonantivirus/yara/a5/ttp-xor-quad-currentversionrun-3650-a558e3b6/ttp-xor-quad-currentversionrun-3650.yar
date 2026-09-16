rule TTP_XOR_QUAD_CurrentVersionRun_3650 {
  strings:
    $key_3650 = { 65 3f [2] 41 31 [2] 6a 1d [2] 44 3f [2] 50 24 [2] 5f 3e [2] 41 23 [2] 43 22 [2] 58 24 [2] 44 23 [2] 58 0c }

  condition:
    any of them
}