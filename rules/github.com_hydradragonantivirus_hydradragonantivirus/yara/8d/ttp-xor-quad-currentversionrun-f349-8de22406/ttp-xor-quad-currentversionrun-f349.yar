rule TTP_XOR_QUAD_CurrentVersionRun_f349 {
  strings:
    $key_f349 = { a0 26 [2] 84 28 [2] af 04 [2] 81 26 [2] 95 3d [2] 9a 27 [2] 84 3a [2] 86 3b [2] 9d 3d [2] 81 3a [2] 9d 15 }

  condition:
    any of them
}