rule TTP_XOR_QUAD_CurrentVersionRun_7ffa {
  strings:
    $key_7ffa = { 2c 95 [2] 08 9b [2] 23 b7 [2] 0d 95 [2] 19 8e [2] 16 94 [2] 08 89 [2] 0a 88 [2] 11 8e [2] 0d 89 [2] 11 a6 }

  condition:
    any of them
}