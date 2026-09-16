rule TTP_XOR_QUAD_CurrentVersionRun_e3e4 {
  strings:
    $key_e3e4 = { b0 8b [2] 94 85 [2] bf a9 [2] 91 8b [2] 85 90 [2] 8a 8a [2] 94 97 [2] 96 96 [2] 8d 90 [2] 91 97 [2] 8d b8 }

  condition:
    any of them
}