rule TTP_XOR_QUAD_CurrentVersionRun_f30b {
  strings:
    $key_f30b = { a0 64 [2] 84 6a [2] af 46 [2] 81 64 [2] 95 7f [2] 9a 65 [2] 84 78 [2] 86 79 [2] 9d 7f [2] 81 78 [2] 9d 57 }

  condition:
    any of them
}