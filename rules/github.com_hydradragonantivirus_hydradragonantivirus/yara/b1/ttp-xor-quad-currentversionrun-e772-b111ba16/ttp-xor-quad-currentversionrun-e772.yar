rule TTP_XOR_QUAD_CurrentVersionRun_e772 {
  strings:
    $key_e772 = { b4 1d [2] 90 13 [2] bb 3f [2] 95 1d [2] 81 06 [2] 8e 1c [2] 90 01 [2] 92 00 [2] 89 06 [2] 95 01 [2] 89 2e }

  condition:
    any of them
}