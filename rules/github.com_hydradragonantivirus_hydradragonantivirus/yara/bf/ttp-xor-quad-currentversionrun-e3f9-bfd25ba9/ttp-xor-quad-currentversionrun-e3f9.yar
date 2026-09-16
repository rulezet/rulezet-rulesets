rule TTP_XOR_QUAD_CurrentVersionRun_e3f9 {
  strings:
    $key_e3f9 = { b0 96 [2] 94 98 [2] bf b4 [2] 91 96 [2] 85 8d [2] 8a 97 [2] 94 8a [2] 96 8b [2] 8d 8d [2] 91 8a [2] 8d a5 }

  condition:
    any of them
}