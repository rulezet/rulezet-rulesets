rule TTP_XOR_MULT_DOSStub_6083 {
  strings:
    $key_6083 = { 34 eb [2] 40 f3 [2] 07 f1 [2] 40 e0 [2] 0e ec [2] 02 e6 [2] 15 ed [2] 0e a3 [2] 33 }

  condition:
    any of them
}