rule TTP_XOR_QUAD_CurrentVersionRun_2040 {
  strings:
    $key_2040 = { 73 2f [2] 57 21 [2] 7c 0d [2] 52 2f [2] 46 34 [2] 49 2e [2] 57 33 [2] 55 32 [2] 4e 34 [2] 52 33 [2] 4e 1c }

  condition:
    any of them
}