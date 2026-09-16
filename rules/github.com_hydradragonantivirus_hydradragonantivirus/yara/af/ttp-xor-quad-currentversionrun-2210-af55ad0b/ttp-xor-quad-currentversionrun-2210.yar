rule TTP_XOR_QUAD_CurrentVersionRun_2210 {
  strings:
    $key_2210 = { 71 7f [2] 55 71 [2] 7e 5d [2] 50 7f [2] 44 64 [2] 4b 7e [2] 55 63 [2] 57 62 [2] 4c 64 [2] 50 63 [2] 4c 4c }

  condition:
    any of them
}