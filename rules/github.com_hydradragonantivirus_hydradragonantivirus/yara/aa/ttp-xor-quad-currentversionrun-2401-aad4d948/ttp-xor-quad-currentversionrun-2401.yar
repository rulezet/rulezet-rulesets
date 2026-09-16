rule TTP_XOR_QUAD_CurrentVersionRun_2401 {
  strings:
    $key_2401 = { 77 6e [2] 53 60 [2] 78 4c [2] 56 6e [2] 42 75 [2] 4d 6f [2] 53 72 [2] 51 73 [2] 4a 75 [2] 56 72 [2] 4a 5d }

  condition:
    any of them
}