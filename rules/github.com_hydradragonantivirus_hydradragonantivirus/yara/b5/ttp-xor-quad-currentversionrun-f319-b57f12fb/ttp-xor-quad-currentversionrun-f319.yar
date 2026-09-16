rule TTP_XOR_QUAD_CurrentVersionRun_f319 {
  strings:
    $key_f319 = { a0 76 [2] 84 78 [2] af 54 [2] 81 76 [2] 95 6d [2] 9a 77 [2] 84 6a [2] 86 6b [2] 9d 6d [2] 81 6a [2] 9d 45 }

  condition:
    any of them
}