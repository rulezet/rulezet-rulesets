rule TTP_XOR_MULT_DOSStub_9400 {
  strings:
    $key_9400 = { c0 68 [2] b4 70 [2] f3 72 [2] b4 63 [2] fa 6f [2] f6 65 [2] e1 6e [2] fa 20 [2] c7 }

  condition:
    any of them
}