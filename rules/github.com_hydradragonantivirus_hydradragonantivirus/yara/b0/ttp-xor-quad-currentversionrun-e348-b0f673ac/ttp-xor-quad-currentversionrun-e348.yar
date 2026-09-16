rule TTP_XOR_QUAD_CurrentVersionRun_e348 {
  strings:
    $key_e348 = { b0 27 [2] 94 29 [2] bf 05 [2] 91 27 [2] 85 3c [2] 8a 26 [2] 94 3b [2] 96 3a [2] 8d 3c [2] 91 3b [2] 8d 14 }

  condition:
    any of them
}