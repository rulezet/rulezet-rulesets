rule TTP_XOR_MULT_DOSStub_8283 {
  strings:
    $key_8283 = { d6 eb [2] a2 f3 [2] e5 f1 [2] a2 e0 [2] ec ec [2] e0 e6 [2] f7 ed [2] ec a3 [2] d1 }

  condition:
    any of them
}