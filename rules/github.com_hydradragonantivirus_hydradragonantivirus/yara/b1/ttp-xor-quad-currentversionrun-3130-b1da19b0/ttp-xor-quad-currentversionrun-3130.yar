rule TTP_XOR_QUAD_CurrentVersionRun_3130 {
  strings:
    $key_3130 = { 62 5f [2] 46 51 [2] 6d 7d [2] 43 5f [2] 57 44 [2] 58 5e [2] 46 43 [2] 44 42 [2] 5f 44 [2] 43 43 [2] 5f 6c }

  condition:
    any of them
}