rule TTP_XOR_QUAD_CurrentVersionRun_3950 {
  strings:
    $key_3950 = { 6a 3f [2] 4e 31 [2] 65 1d [2] 4b 3f [2] 5f 24 [2] 50 3e [2] 4e 23 [2] 4c 22 [2] 57 24 [2] 4b 23 [2] 57 0c }

  condition:
    any of them
}