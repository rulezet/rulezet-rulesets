rule TTP_XOR_QUAD_CurrentVersionRun_f314 {
  strings:
    $key_f314 = { a0 7b [2] 84 75 [2] af 59 [2] 81 7b [2] 95 60 [2] 9a 7a [2] 84 67 [2] 86 66 [2] 9d 60 [2] 81 67 [2] 9d 48 }

  condition:
    any of them
}