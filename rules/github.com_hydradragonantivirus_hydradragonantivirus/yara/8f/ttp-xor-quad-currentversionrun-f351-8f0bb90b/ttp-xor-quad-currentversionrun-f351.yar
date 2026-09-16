rule TTP_XOR_QUAD_CurrentVersionRun_f351 {
  strings:
    $key_f351 = { a0 3e [2] 84 30 [2] af 1c [2] 81 3e [2] 95 25 [2] 9a 3f [2] 84 22 [2] 86 23 [2] 9d 25 [2] 81 22 [2] 9d 0d }

  condition:
    any of them
}