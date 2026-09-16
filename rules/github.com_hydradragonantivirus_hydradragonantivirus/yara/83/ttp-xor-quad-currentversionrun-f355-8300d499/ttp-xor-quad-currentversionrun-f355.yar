rule TTP_XOR_QUAD_CurrentVersionRun_f355 {
  strings:
    $key_f355 = { a0 3a [2] 84 34 [2] af 18 [2] 81 3a [2] 95 21 [2] 9a 3b [2] 84 26 [2] 86 27 [2] 9d 21 [2] 81 26 [2] 9d 09 }

  condition:
    any of them
}