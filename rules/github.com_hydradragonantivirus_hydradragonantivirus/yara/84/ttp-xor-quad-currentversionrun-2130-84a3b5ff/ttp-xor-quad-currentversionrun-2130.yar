rule TTP_XOR_QUAD_CurrentVersionRun_2130 {
  strings:
    $key_2130 = { 72 5f [2] 56 51 [2] 7d 7d [2] 53 5f [2] 47 44 [2] 48 5e [2] 56 43 [2] 54 42 [2] 4f 44 [2] 53 43 [2] 4f 6c }

  condition:
    any of them
}