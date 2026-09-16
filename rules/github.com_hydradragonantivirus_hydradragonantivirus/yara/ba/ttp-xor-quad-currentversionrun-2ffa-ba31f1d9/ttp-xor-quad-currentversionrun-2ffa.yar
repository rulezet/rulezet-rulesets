rule TTP_XOR_QUAD_CurrentVersionRun_2ffa {
  strings:
    $key_2ffa = { 7c 95 [2] 58 9b [2] 73 b7 [2] 5d 95 [2] 49 8e [2] 46 94 [2] 58 89 [2] 5a 88 [2] 41 8e [2] 5d 89 [2] 41 a6 }

  condition:
    any of them
}