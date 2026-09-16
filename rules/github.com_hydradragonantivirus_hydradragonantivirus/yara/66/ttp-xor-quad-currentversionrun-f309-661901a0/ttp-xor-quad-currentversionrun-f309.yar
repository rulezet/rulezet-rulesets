rule TTP_XOR_QUAD_CurrentVersionRun_f309 {
  strings:
    $key_f309 = { a0 66 [2] 84 68 [2] af 44 [2] 81 66 [2] 95 7d [2] 9a 67 [2] 84 7a [2] 86 7b [2] 9d 7d [2] 81 7a [2] 9d 55 }

  condition:
    any of them
}