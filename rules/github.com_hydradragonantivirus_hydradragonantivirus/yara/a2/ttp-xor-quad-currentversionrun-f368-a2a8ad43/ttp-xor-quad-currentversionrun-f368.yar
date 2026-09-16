rule TTP_XOR_QUAD_CurrentVersionRun_f368 {
  strings:
    $key_f368 = { a0 07 [2] 84 09 [2] af 25 [2] 81 07 [2] 95 1c [2] 9a 06 [2] 84 1b [2] 86 1a [2] 9d 1c [2] 81 1b [2] 9d 34 }

  condition:
    any of them
}