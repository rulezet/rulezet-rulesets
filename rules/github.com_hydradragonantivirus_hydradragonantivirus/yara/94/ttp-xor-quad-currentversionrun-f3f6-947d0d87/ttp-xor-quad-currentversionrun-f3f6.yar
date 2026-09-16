rule TTP_XOR_QUAD_CurrentVersionRun_f3f6 {
  strings:
    $key_f3f6 = { a0 99 [2] 84 97 [2] af bb [2] 81 99 [2] 95 82 [2] 9a 98 [2] 84 85 [2] 86 84 [2] 9d 82 [2] 81 85 [2] 9d aa }

  condition:
    any of them
}