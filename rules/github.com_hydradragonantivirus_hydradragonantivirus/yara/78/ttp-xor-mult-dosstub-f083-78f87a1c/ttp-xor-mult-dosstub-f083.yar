rule TTP_XOR_MULT_DOSStub_f083 {
  strings:
    $key_f083 = { a4 eb [2] d0 f3 [2] 97 f1 [2] d0 e0 [2] 9e ec [2] 92 e6 [2] 85 ed [2] 9e a3 [2] a3 }

  condition:
    any of them
}