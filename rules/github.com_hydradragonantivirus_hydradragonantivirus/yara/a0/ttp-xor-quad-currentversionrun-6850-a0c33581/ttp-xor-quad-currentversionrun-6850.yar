rule TTP_XOR_QUAD_CurrentVersionRun_6850 {
  strings:
    $key_6850 = { 3b 3f [2] 1f 31 [2] 34 1d [2] 1a 3f [2] 0e 24 [2] 01 3e [2] 1f 23 [2] 1d 22 [2] 06 24 [2] 1a 23 [2] 06 0c }

  condition:
    any of them
}