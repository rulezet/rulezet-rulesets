rule TTP_XOR_QUAD_CurrentVersionRun_cd99 {
  strings:
    $key_cd99 = { 9e f6 [2] ba f8 [2] 91 d4 [2] bf f6 [2] ab ed [2] a4 f7 [2] ba ea [2] b8 eb [2] a3 ed [2] bf ea [2] a3 c5 }

  condition:
    any of them
}