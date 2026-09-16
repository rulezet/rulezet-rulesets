rule TTP_XOR_QUAD_CurrentVersionRun_8199 {
  strings:
    $key_8199 = { d2 f6 [2] f6 f8 [2] dd d4 [2] f3 f6 [2] e7 ed [2] e8 f7 [2] f6 ea [2] f4 eb [2] ef ed [2] f3 ea [2] ef c5 }

  condition:
    any of them
}