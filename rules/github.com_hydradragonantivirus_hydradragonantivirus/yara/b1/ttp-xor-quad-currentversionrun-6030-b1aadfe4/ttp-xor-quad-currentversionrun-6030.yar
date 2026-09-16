rule TTP_XOR_QUAD_CurrentVersionRun_6030 {
  strings:
    $key_6030 = { 33 5f [2] 17 51 [2] 3c 7d [2] 12 5f [2] 06 44 [2] 09 5e [2] 17 43 [2] 15 42 [2] 0e 44 [2] 12 43 [2] 0e 6c }

  condition:
    any of them
}