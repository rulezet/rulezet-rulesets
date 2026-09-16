rule TTP_XOR_QUAD_CurrentVersionRun_ef48 {
  strings:
    $key_ef48 = { bc 27 [2] 98 29 [2] b3 05 [2] 9d 27 [2] 89 3c [2] 86 26 [2] 98 3b [2] 9a 3a [2] 81 3c [2] 9d 3b [2] 81 14 }

  condition:
    any of them
}