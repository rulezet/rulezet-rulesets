rule TTP_XOR_QUAD_CurrentVersionRun_f357 {
  strings:
    $key_f357 = { a0 38 [2] 84 36 [2] af 1a [2] 81 38 [2] 95 23 [2] 9a 39 [2] 84 24 [2] 86 25 [2] 9d 23 [2] 81 24 [2] 9d 0b }

  condition:
    any of them
}