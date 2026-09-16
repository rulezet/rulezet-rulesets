rule TTP_XOR_QUAD_CurrentVersionRun_2a2a {
  strings:
    $key_2a2a = { 79 45 [2] 5d 4b [2] 76 67 [2] 58 45 [2] 4c 5e [2] 43 44 [2] 5d 59 [2] 5f 58 [2] 44 5e [2] 58 59 [2] 44 76 }

  condition:
    any of them
}