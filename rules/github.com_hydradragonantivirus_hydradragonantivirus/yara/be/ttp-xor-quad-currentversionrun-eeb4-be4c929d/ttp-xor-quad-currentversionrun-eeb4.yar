rule TTP_XOR_QUAD_CurrentVersionRun_eeb4 {
  strings:
    $key_eeb4 = { bd db [2] 99 d5 [2] b2 f9 [2] 9c db [2] 88 c0 [2] 87 da [2] 99 c7 [2] 9b c6 [2] 80 c0 [2] 9c c7 [2] 80 e8 }

  condition:
    any of them
}