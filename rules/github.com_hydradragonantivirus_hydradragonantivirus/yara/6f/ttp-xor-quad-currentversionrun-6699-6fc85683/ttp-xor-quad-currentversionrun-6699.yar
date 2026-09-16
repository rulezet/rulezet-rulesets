rule TTP_XOR_QUAD_CurrentVersionRun_6699 {
  strings:
    $key_6699 = { 35 f6 [2] 11 f8 [2] 3a d4 [2] 14 f6 [2] 00 ed [2] 0f f7 [2] 11 ea [2] 13 eb [2] 08 ed [2] 14 ea [2] 08 c5 }

  condition:
    any of them
}