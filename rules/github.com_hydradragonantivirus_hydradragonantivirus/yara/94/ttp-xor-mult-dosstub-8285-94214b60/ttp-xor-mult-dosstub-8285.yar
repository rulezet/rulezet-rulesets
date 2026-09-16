rule TTP_XOR_MULT_DOSStub_8285 {
  strings:
    $key_8285 = { d6 ed [2] a2 f5 [2] e5 f7 [2] a2 e6 [2] ec ea [2] e0 e0 [2] f7 eb [2] ec a5 [2] d1 }

  condition:
    any of them
}