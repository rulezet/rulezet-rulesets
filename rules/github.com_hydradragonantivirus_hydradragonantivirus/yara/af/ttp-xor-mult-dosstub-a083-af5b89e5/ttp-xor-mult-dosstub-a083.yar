rule TTP_XOR_MULT_DOSStub_a083 {
  strings:
    $key_a083 = { f4 eb [2] 80 f3 [2] c7 f1 [2] 80 e0 [2] ce ec [2] c2 e6 [2] d5 ed [2] ce a3 [2] f3 }

  condition:
    any of them
}