rule TTP_XOR_QUAD_CurrentVersionRun_f34b {
  strings:
    $key_f34b = { a0 24 [2] 84 2a [2] af 06 [2] 81 24 [2] 95 3f [2] 9a 25 [2] 84 38 [2] 86 39 [2] 9d 3f [2] 81 38 [2] 9d 17 }

  condition:
    any of them
}