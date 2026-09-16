rule TTP_XOR_QUAD_CurrentVersionRun_2a31 {
  strings:
    $key_2a31 = { 79 5e [2] 5d 50 [2] 76 7c [2] 58 5e [2] 4c 45 [2] 43 5f [2] 5d 42 [2] 5f 43 [2] 44 45 [2] 58 42 [2] 44 6d }

  condition:
    any of them
}