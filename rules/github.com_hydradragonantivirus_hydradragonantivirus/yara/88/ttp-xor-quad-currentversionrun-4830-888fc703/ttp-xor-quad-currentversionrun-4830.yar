rule TTP_XOR_QUAD_CurrentVersionRun_4830 {
  strings:
    $key_4830 = { 1b 5f [2] 3f 51 [2] 14 7d [2] 3a 5f [2] 2e 44 [2] 21 5e [2] 3f 43 [2] 3d 42 [2] 26 44 [2] 3a 43 [2] 26 6c }

  condition:
    any of them
}