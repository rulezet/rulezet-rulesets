rule TTP_XOR_MULT_DOSStub_9431 {
  strings:
    $key_9431 = { c0 59 [2] b4 41 [2] f3 43 [2] b4 52 [2] fa 5e [2] f6 54 [2] e1 5f [2] fa 11 [2] c7 }

  condition:
    any of them
}