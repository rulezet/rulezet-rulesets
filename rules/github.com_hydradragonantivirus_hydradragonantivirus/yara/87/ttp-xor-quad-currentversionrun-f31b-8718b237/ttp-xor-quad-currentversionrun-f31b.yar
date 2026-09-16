rule TTP_XOR_QUAD_CurrentVersionRun_f31b {
  strings:
    $key_f31b = { a0 74 [2] 84 7a [2] af 56 [2] 81 74 [2] 95 6f [2] 9a 75 [2] 84 68 [2] 86 69 [2] 9d 6f [2] 81 68 [2] 9d 47 }

  condition:
    any of them
}