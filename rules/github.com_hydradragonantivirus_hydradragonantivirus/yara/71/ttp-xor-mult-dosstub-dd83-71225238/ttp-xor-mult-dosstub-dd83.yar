rule TTP_XOR_MULT_DOSStub_dd83 {
  strings:
    $key_dd83 = { 89 eb [2] fd f3 [2] ba f1 [2] fd e0 [2] b3 ec [2] bf e6 [2] a8 ed [2] b3 a3 [2] 8e }

  condition:
    any of them
}