rule TTP_XOR_QUAD_CurrentVersionRun_3ffa {
  strings:
    $key_3ffa = { 6c 95 [2] 48 9b [2] 63 b7 [2] 4d 95 [2] 59 8e [2] 56 94 [2] 48 89 [2] 4a 88 [2] 51 8e [2] 4d 89 [2] 51 a6 }

  condition:
    any of them
}