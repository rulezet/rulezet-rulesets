rule TTP_XOR_QUAD_CurrentVersionRun_3101 {
  strings:
    $key_3101 = { 62 6e [2] 46 60 [2] 6d 4c [2] 43 6e [2] 57 75 [2] 58 6f [2] 46 72 [2] 44 73 [2] 5f 75 [2] 43 72 [2] 5f 5d }

  condition:
    any of them
}