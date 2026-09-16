rule TTP_XOR_QUAD_CurrentVersionRun_8d99 {
  strings:
    $key_8d99 = { de f6 [2] fa f8 [2] d1 d4 [2] ff f6 [2] eb ed [2] e4 f7 [2] fa ea [2] f8 eb [2] e3 ed [2] ff ea [2] e3 c5 }

  condition:
    any of them
}