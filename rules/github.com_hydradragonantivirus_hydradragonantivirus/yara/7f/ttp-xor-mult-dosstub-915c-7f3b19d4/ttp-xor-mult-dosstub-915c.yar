rule TTP_XOR_MULT_DOSStub_915c {
  strings:
    $key_915c = { c5 34 [2] b1 2c [2] f6 2e [2] b1 3f [2] ff 33 [2] f3 39 [2] e4 32 [2] ff 7c [2] c2 }

  condition:
    any of them
}