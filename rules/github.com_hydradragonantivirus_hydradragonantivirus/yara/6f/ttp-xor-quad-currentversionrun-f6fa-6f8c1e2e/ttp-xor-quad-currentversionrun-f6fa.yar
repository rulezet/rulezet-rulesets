rule TTP_XOR_QUAD_CurrentVersionRun_f6fa {
  strings:
    $key_f6fa = { a5 95 [2] 81 9b [2] aa b7 [2] 84 95 [2] 90 8e [2] 9f 94 [2] 81 89 [2] 83 88 [2] 98 8e [2] 84 89 [2] 98 a6 }

  condition:
    any of them
}