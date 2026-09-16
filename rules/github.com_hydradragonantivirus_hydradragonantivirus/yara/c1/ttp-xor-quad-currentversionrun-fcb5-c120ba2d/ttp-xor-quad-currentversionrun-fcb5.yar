rule TTP_XOR_QUAD_CurrentVersionRun_fcb5 {
  strings:
    $key_fcb5 = { af da [2] 8b d4 [2] a0 f8 [2] 8e da [2] 9a c1 [2] 95 db [2] 8b c6 [2] 89 c7 [2] 92 c1 [2] 8e c6 [2] 92 e9 }

  condition:
    any of them
}