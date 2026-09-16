rule TTP_XOR_QUAD_CurrentVersionRun_3850 {
  strings:
    $key_3850 = { 6b 3f [2] 4f 31 [2] 64 1d [2] 4a 3f [2] 5e 24 [2] 51 3e [2] 4f 23 [2] 4d 22 [2] 56 24 [2] 4a 23 [2] 56 0c }

  condition:
    any of them
}