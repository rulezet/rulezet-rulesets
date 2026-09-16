rule TTP_XOR_QUAD_CurrentVersionRun_f317 {
  strings:
    $key_f317 = { a0 78 [2] 84 76 [2] af 5a [2] 81 78 [2] 95 63 [2] 9a 79 [2] 84 64 [2] 86 65 [2] 9d 63 [2] 81 64 [2] 9d 4b }

  condition:
    any of them
}