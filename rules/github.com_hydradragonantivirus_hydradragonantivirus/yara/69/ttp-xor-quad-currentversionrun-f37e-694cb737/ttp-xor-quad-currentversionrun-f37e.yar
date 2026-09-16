rule TTP_XOR_QUAD_CurrentVersionRun_f37e {
  strings:
    $key_f37e = { a0 11 [2] 84 1f [2] af 33 [2] 81 11 [2] 95 0a [2] 9a 10 [2] 84 0d [2] 86 0c [2] 9d 0a [2] 81 0d [2] 9d 22 }

  condition:
    any of them
}