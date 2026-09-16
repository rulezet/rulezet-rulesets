rule TTP_XOR_QUAD_CurrentVersionRun_2623 {
  strings:
    $key_2623 = { 75 4c [2] 51 42 [2] 7a 6e [2] 54 4c [2] 40 57 [2] 4f 4d [2] 51 50 [2] 53 51 [2] 48 57 [2] 54 50 [2] 48 7f }

  condition:
    any of them
}