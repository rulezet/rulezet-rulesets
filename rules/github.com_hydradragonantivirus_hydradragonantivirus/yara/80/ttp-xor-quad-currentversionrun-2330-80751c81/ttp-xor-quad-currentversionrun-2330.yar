rule TTP_XOR_QUAD_CurrentVersionRun_2330 {
  strings:
    $key_2330 = { 70 5f [2] 54 51 [2] 7f 7d [2] 51 5f [2] 45 44 [2] 4a 5e [2] 54 43 [2] 56 42 [2] 4d 44 [2] 51 43 [2] 4d 6c }

  condition:
    any of them
}