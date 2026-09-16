rule TTP_XOR_QUAD_CurrentVersionRun_f672 {
  strings:
    $key_f672 = { a5 1d [2] 81 13 [2] aa 3f [2] 84 1d [2] 90 06 [2] 9f 1c [2] 81 01 [2] 83 00 [2] 98 06 [2] 84 01 [2] 98 2e }

  condition:
    any of them
}