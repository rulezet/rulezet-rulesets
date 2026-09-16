rule TTP_XOR_QUAD_CurrentVersionRun_f307 {
  strings:
    $key_f307 = { a0 68 [2] 84 66 [2] af 4a [2] 81 68 [2] 95 73 [2] 9a 69 [2] 84 74 [2] 86 75 [2] 9d 73 [2] 81 74 [2] 9d 5b }

  condition:
    any of them
}