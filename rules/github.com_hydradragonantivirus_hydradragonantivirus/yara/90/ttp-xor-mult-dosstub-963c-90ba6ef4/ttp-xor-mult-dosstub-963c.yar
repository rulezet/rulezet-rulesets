rule TTP_XOR_MULT_DOSStub_963c {
  strings:
    $key_963c = { c2 54 [2] b6 4c [2] f1 4e [2] b6 5f [2] f8 53 [2] f4 59 [2] e3 52 [2] f8 1c [2] c5 }

  condition:
    any of them
}