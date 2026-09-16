rule TTP_XOR_QUAD_CurrentVersionRun_f318 {
  strings:
    $key_f318 = { a0 77 [2] 84 79 [2] af 55 [2] 81 77 [2] 95 6c [2] 9a 76 [2] 84 6b [2] 86 6a [2] 9d 6c [2] 81 6b [2] 9d 44 }

  condition:
    any of them
}