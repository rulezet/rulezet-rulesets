rule TTP_XOR_MULT_DOSStub_f5ca {
  strings:
    $key_f5ca = { a1 a2 [2] d5 ba [2] 92 b8 [2] d5 a9 [2] 9b a5 [2] 97 af [2] 80 a4 [2] 9b ea [2] a6 }

  condition:
    any of them
}