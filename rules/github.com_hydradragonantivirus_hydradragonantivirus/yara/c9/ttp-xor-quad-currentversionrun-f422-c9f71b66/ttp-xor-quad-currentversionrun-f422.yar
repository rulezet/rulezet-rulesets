rule TTP_XOR_QUAD_CurrentVersionRun_f422 {
  strings:
    $key_f422 = { a7 4d [2] 83 43 [2] a8 6f [2] 86 4d [2] 92 56 [2] 9d 4c [2] 83 51 [2] 81 50 [2] 9a 56 [2] 86 51 [2] 9a 7e }

  condition:
    any of them
}