rule TTP_XOR_QUAD_CurrentVersionRun_2200 {
  strings:
    $key_2200 = { 71 6f [2] 55 61 [2] 7e 4d [2] 50 6f [2] 44 74 [2] 4b 6e [2] 55 73 [2] 57 72 [2] 4c 74 [2] 50 73 [2] 4c 5c }

  condition:
    any of them
}