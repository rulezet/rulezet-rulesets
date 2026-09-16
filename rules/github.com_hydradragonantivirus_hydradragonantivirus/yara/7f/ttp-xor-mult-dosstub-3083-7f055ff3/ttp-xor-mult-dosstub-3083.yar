rule TTP_XOR_MULT_DOSStub_3083 {
  strings:
    $key_3083 = { 64 eb [2] 10 f3 [2] 57 f1 [2] 10 e0 [2] 5e ec [2] 52 e6 [2] 45 ed [2] 5e a3 [2] 63 }

  condition:
    any of them
}