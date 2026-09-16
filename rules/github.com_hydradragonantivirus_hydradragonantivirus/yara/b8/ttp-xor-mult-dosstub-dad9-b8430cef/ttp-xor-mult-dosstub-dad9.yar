rule TTP_XOR_MULT_DOSStub_dad9 {
  strings:
    $key_dad9 = { 8e b1 [2] fa a9 [2] bd ab [2] fa ba [2] b4 b6 [2] b8 bc [2] af b7 [2] b4 f9 [2] 89 }

  condition:
    any of them
}