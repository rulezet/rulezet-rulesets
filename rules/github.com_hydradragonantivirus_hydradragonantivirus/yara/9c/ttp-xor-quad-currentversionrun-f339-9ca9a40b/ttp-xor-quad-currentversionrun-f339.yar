rule TTP_XOR_QUAD_CurrentVersionRun_f339 {
  strings:
    $key_f339 = { a0 56 [2] 84 58 [2] af 74 [2] 81 56 [2] 95 4d [2] 9a 57 [2] 84 4a [2] 86 4b [2] 9d 4d [2] 81 4a [2] 9d 65 }

  condition:
    any of them
}