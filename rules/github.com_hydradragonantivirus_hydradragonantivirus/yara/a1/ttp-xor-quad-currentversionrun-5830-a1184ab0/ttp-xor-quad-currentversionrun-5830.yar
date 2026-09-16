rule TTP_XOR_QUAD_CurrentVersionRun_5830 {
  strings:
    $key_5830 = { 0b 5f [2] 2f 51 [2] 04 7d [2] 2a 5f [2] 3e 44 [2] 31 5e [2] 2f 43 [2] 2d 42 [2] 36 44 [2] 2a 43 [2] 36 6c }

  condition:
    any of them
}