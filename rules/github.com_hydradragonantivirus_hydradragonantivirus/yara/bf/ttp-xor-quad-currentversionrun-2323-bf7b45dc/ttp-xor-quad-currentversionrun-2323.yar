rule TTP_XOR_QUAD_CurrentVersionRun_2323 {
  strings:
    $key_2323 = { 70 4c [2] 54 42 [2] 7f 6e [2] 51 4c [2] 45 57 [2] 4a 4d [2] 54 50 [2] 56 51 [2] 4d 57 [2] 51 50 [2] 4d 7f }

  condition:
    any of them
}