rule TTP_XOR_MULT_DOSStub_cf82 {
  strings:
    $key_cf82 = { 9b ea [2] ef f2 [2] a8 f0 [2] ef e1 [2] a1 ed [2] ad e7 [2] ba ec [2] a1 a2 [2] 9c }

  condition:
    any of them
}