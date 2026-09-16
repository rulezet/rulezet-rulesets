rule TTP_XOR_QUAD_CurrentVersionRun_2830 {
  strings:
    $key_2830 = { 7b 5f [2] 5f 51 [2] 74 7d [2] 5a 5f [2] 4e 44 [2] 41 5e [2] 5f 43 [2] 5d 42 [2] 46 44 [2] 5a 43 [2] 46 6c }

  condition:
    any of them
}