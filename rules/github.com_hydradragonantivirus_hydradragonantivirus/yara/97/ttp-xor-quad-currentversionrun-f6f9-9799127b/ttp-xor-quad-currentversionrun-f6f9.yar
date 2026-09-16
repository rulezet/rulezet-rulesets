rule TTP_XOR_QUAD_CurrentVersionRun_f6f9 {
  strings:
    $key_f6f9 = { a5 96 [2] 81 98 [2] aa b4 [2] 84 96 [2] 90 8d [2] 9f 97 [2] 81 8a [2] 83 8b [2] 98 8d [2] 84 8a [2] 98 a5 }

  condition:
    any of them
}