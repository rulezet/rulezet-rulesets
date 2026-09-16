rule TTP_XOR_QUAD_CurrentVersionRun_f37a {
  strings:
    $key_f37a = { a0 15 [2] 84 1b [2] af 37 [2] 81 15 [2] 95 0e [2] 9a 14 [2] 84 09 [2] 86 08 [2] 9d 0e [2] 81 09 [2] 9d 26 }

  condition:
    any of them
}