rule TTP_XOR_QUAD_CurrentVersionRun_f3f8 {
  strings:
    $key_f3f8 = { a0 97 [2] 84 99 [2] af b5 [2] 81 97 [2] 95 8c [2] 9a 96 [2] 84 8b [2] 86 8a [2] 9d 8c [2] 81 8b [2] 9d a4 }

  condition:
    any of them
}