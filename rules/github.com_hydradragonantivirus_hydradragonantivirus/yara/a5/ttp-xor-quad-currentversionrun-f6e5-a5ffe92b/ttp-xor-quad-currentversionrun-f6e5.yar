rule TTP_XOR_QUAD_CurrentVersionRun_f6e5 {
  strings:
    $key_f6e5 = { a5 8a [2] 81 84 [2] aa a8 [2] 84 8a [2] 90 91 [2] 9f 8b [2] 81 96 [2] 83 97 [2] 98 91 [2] 84 96 [2] 98 b9 }

  condition:
    any of them
}