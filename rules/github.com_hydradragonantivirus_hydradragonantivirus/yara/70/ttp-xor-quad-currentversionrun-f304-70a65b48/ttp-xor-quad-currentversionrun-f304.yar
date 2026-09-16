rule TTP_XOR_QUAD_CurrentVersionRun_f304 {
  strings:
    $key_f304 = { a0 6b [2] 84 65 [2] af 49 [2] 81 6b [2] 95 70 [2] 9a 6a [2] 84 77 [2] 86 76 [2] 9d 70 [2] 81 77 [2] 9d 58 }

  condition:
    any of them
}