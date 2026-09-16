rule TTP_XOR_QUAD_CurrentVersionRun_e3f4 {
  strings:
    $key_e3f4 = { b0 9b [2] 94 95 [2] bf b9 [2] 91 9b [2] 85 80 [2] 8a 9a [2] 94 87 [2] 96 86 [2] 8d 80 [2] 91 87 [2] 8d a8 }

  condition:
    any of them
}