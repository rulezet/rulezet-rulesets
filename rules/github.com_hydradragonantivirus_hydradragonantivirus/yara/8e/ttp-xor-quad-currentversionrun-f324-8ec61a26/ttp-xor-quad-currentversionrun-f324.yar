rule TTP_XOR_QUAD_CurrentVersionRun_f324 {
  strings:
    $key_f324 = { a0 4b [2] 84 45 [2] af 69 [2] 81 4b [2] 95 50 [2] 9a 4a [2] 84 57 [2] 86 56 [2] 9d 50 [2] 81 57 [2] 9d 78 }

  condition:
    any of them
}