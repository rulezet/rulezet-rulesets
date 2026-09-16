rule TTP_XOR_MULT_DOSStub_8ab2 {
  strings:
    $key_8ab2 = { de da [2] aa c2 [2] ed c0 [2] aa d1 [2] e4 dd [2] e8 d7 [2] ff dc [2] e4 92 [2] d9 }

  condition:
    any of them
}