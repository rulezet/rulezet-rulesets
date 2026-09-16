rule TTP_XOR_QUAD_CurrentVersionRun_f572 {
  strings:
    $key_f572 = { a6 1d [2] 82 13 [2] a9 3f [2] 87 1d [2] 93 06 [2] 9c 1c [2] 82 01 [2] 80 00 [2] 9b 06 [2] 87 01 [2] 9b 2e }

  condition:
    any of them
}