rule TTP_XOR_QUAD_CurrentVersionRun_6199 {
  strings:
    $key_6199 = { 32 f6 [2] 16 f8 [2] 3d d4 [2] 13 f6 [2] 07 ed [2] 08 f7 [2] 16 ea [2] 14 eb [2] 0f ed [2] 13 ea [2] 0f c5 }

  condition:
    any of them
}