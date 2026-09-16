rule TTP_XOR_MULT_DOSStub_962c {
  strings:
    $key_962c = { c2 44 [2] b6 5c [2] f1 5e [2] b6 4f [2] f8 43 [2] f4 49 [2] e3 42 [2] f8 0c [2] c5 }

  condition:
    any of them
}