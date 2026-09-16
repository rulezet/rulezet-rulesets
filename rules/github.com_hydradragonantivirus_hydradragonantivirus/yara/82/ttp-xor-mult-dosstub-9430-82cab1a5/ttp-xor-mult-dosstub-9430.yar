rule TTP_XOR_MULT_DOSStub_9430 {
  strings:
    $key_9430 = { c0 58 [2] b4 40 [2] f3 42 [2] b4 53 [2] fa 5f [2] f6 55 [2] e1 5e [2] fa 10 [2] c7 }

  condition:
    any of them
}