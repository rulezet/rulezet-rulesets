rule TTP_XOR_QUAD_CurrentVersionRun_e3d2 {
  strings:
    $key_e3d2 = { b0 bd [2] 94 b3 [2] bf 9f [2] 91 bd [2] 85 a6 [2] 8a bc [2] 94 a1 [2] 96 a0 [2] 8d a6 [2] 91 a1 [2] 8d 8e }

  condition:
    any of them
}