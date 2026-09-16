rule TTP_XOR_QUAD_CurrentVersionRun_f3f0 {
  strings:
    $key_f3f0 = { a0 9f [2] 84 91 [2] af bd [2] 81 9f [2] 95 84 [2] 9a 9e [2] 84 83 [2] 86 82 [2] 9d 84 [2] 81 83 [2] 9d ac }

  condition:
    any of them
}