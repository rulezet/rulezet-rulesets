rule TTP_XOR_QUAD_CurrentVersionRun_2a21 {
  strings:
    $key_2a21 = { 79 4e [2] 5d 40 [2] 76 6c [2] 58 4e [2] 4c 55 [2] 43 4f [2] 5d 52 [2] 5f 53 [2] 44 55 [2] 58 52 [2] 44 7d }

  condition:
    any of them
}