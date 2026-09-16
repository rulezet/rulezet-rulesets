rule TTP_XOR_QUAD_CurrentVersionRun_f303 {
  strings:
    $key_f303 = { a0 6c [2] 84 62 [2] af 4e [2] 81 6c [2] 95 77 [2] 9a 6d [2] 84 70 [2] 86 71 [2] 9d 77 [2] 81 70 [2] 9d 5f }

  condition:
    any of them
}