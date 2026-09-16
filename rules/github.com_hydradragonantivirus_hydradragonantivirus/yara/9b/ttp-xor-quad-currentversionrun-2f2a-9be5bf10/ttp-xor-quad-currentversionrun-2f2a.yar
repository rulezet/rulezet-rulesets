rule TTP_XOR_QUAD_CurrentVersionRun_2f2a {
  strings:
    $key_2f2a = { 7c 45 [2] 58 4b [2] 73 67 [2] 5d 45 [2] 49 5e [2] 46 44 [2] 58 59 [2] 5a 58 [2] 41 5e [2] 5d 59 [2] 41 76 }

  condition:
    any of them
}