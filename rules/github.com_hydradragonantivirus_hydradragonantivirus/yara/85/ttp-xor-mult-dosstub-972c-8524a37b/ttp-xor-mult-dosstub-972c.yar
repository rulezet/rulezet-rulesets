rule TTP_XOR_MULT_DOSStub_972c {
  strings:
    $key_972c = { c3 44 [2] b7 5c [2] f0 5e [2] b7 4f [2] f9 43 [2] f5 49 [2] e2 42 [2] f9 0c [2] c4 }

  condition:
    any of them
}