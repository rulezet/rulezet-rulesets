rule TTP_XOR_QUAD_CurrentVersionRun_f333 {
  strings:
    $key_f333 = { a0 5c [2] 84 52 [2] af 7e [2] 81 5c [2] 95 47 [2] 9a 5d [2] 84 40 [2] 86 41 [2] 9d 47 [2] 81 40 [2] 9d 6f }

  condition:
    any of them
}