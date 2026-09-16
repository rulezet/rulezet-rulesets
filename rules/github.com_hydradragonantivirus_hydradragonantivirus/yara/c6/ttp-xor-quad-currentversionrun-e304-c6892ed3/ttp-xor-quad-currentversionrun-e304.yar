rule TTP_XOR_QUAD_CurrentVersionRun_e304 {
  strings:
    $key_e304 = { b0 6b [2] 94 65 [2] bf 49 [2] 91 6b [2] 85 70 [2] 8a 6a [2] 94 77 [2] 96 76 [2] 8d 70 [2] 91 77 [2] 8d 58 }

  condition:
    any of them
}