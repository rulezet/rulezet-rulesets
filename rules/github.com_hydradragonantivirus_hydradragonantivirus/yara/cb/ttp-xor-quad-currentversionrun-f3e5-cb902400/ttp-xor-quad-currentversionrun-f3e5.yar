rule TTP_XOR_QUAD_CurrentVersionRun_f3e5 {
  strings:
    $key_f3e5 = { a0 8a [2] 84 84 [2] af a8 [2] 81 8a [2] 95 91 [2] 9a 8b [2] 84 96 [2] 86 97 [2] 9d 91 [2] 81 96 [2] 9d b9 }

  condition:
    any of them
}