rule TTP_XOR_QUAD_CurrentVersionRun_f6f8 {
  strings:
    $key_f6f8 = { a5 97 [2] 81 99 [2] aa b5 [2] 84 97 [2] 90 8c [2] 9f 96 [2] 81 8b [2] 83 8a [2] 98 8c [2] 84 8b [2] 98 a4 }

  condition:
    any of them
}