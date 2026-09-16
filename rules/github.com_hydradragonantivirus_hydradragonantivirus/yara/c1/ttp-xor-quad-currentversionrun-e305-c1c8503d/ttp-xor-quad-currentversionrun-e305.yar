rule TTP_XOR_QUAD_CurrentVersionRun_e305 {
  strings:
    $key_e305 = { b0 6a [2] 94 64 [2] bf 48 [2] 91 6a [2] 85 71 [2] 8a 6b [2] 94 76 [2] 96 77 [2] 8d 71 [2] 91 76 [2] 8d 59 }

  condition:
    any of them
}