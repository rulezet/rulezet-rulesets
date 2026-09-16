rule TTP_XOR_MULT_DOSStub_917c {
  strings:
    $key_917c = { c5 14 [2] b1 0c [2] f6 0e [2] b1 1f [2] ff 13 [2] f3 19 [2] e4 12 [2] ff 5c [2] c2 }

  condition:
    any of them
}