rule TTP_XOR_QUAD_CurrentVersionRun_e714 {
  strings:
    $key_e714 = { b4 7b [2] 90 75 [2] bb 59 [2] 95 7b [2] 81 60 [2] 8e 7a [2] 90 67 [2] 92 66 [2] 89 60 [2] 95 67 [2] 89 48 }

  condition:
    any of them
}