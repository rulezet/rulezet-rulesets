rule TTP_XOR_QUAD_CurrentVersionRun_4130 {
  strings:
    $key_4130 = { 12 5f [2] 36 51 [2] 1d 7d [2] 33 5f [2] 27 44 [2] 28 5e [2] 36 43 [2] 34 42 [2] 2f 44 [2] 33 43 [2] 2f 6c }

  condition:
    any of them
}