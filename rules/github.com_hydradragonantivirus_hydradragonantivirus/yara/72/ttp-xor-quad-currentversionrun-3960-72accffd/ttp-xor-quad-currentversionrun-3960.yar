rule TTP_XOR_QUAD_CurrentVersionRun_3960 {
  strings:
    $key_3960 = { 6a 0f [2] 4e 01 [2] 65 2d [2] 4b 0f [2] 5f 14 [2] 50 0e [2] 4e 13 [2] 4c 12 [2] 57 14 [2] 4b 13 [2] 57 3c }

  condition:
    any of them
}