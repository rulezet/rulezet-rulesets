rule TTP_XOR_QUAD_CurrentVersionRun_3930 {
  strings:
    $key_3930 = { 6a 5f [2] 4e 51 [2] 65 7d [2] 4b 5f [2] 5f 44 [2] 50 5e [2] 4e 43 [2] 4c 42 [2] 57 44 [2] 4b 43 [2] 57 6c }

  condition:
    any of them
}