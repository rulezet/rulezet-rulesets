rule TTP_XOR_QUAD_CurrentVersionRun_602a {
  strings:
    $key_602a = { 33 45 [2] 17 4b [2] 3c 67 [2] 12 45 [2] 06 5e [2] 09 44 [2] 17 59 [2] 15 58 [2] 0e 5e [2] 12 59 [2] 0e 76 }

  condition:
    any of them
}