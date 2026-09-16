rule TTP_XOR_QUAD_CurrentVersionRun_e3d5 {
  strings:
    $key_e3d5 = { b0 ba [2] 94 b4 [2] bf 98 [2] 91 ba [2] 85 a1 [2] 8a bb [2] 94 a6 [2] 96 a7 [2] 8d a1 [2] 91 a6 [2] 8d 89 }

  condition:
    any of them
}