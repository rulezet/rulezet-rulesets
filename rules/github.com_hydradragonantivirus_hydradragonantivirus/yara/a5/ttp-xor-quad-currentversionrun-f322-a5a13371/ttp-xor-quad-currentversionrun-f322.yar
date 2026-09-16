rule TTP_XOR_QUAD_CurrentVersionRun_f322 {
  strings:
    $key_f322 = { a0 4d [2] 84 43 [2] af 6f [2] 81 4d [2] 95 56 [2] 9a 4c [2] 84 51 [2] 86 50 [2] 9d 56 [2] 81 51 [2] 9d 7e }

  condition:
    any of them
}