rule TTP_XOR_QUAD_CurrentVersionRun_f222 {
  strings:
    $key_f222 = { a1 4d [2] 85 43 [2] ae 6f [2] 80 4d [2] 94 56 [2] 9b 4c [2] 85 51 [2] 87 50 [2] 9c 56 [2] 80 51 [2] 9c 7e }

  condition:
    any of them
}