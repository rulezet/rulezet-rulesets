rule TTP_XOR_QUAD_CurrentVersionRun_e732 {
  strings:
    $key_e732 = { b4 5d [2] 90 53 [2] bb 7f [2] 95 5d [2] 81 46 [2] 8e 5c [2] 90 41 [2] 92 40 [2] 89 46 [2] 95 41 [2] 89 6e }

  condition:
    any of them
}