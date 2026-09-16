rule TTP_XOR_QUAD_CurrentVersionRun_e309 {
  strings:
    $key_e309 = { b0 66 [2] 94 68 [2] bf 44 [2] 91 66 [2] 85 7d [2] 8a 67 [2] 94 7a [2] 96 7b [2] 8d 7d [2] 91 7a [2] 8d 55 }

  condition:
    any of them
}