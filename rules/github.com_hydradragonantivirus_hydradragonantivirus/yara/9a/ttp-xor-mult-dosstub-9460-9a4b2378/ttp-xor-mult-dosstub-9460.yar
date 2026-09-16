rule TTP_XOR_MULT_DOSStub_9460 {
  strings:
    $key_9460 = { c0 08 [2] b4 10 [2] f3 12 [2] b4 03 [2] fa 0f [2] f6 05 [2] e1 0e [2] fa 40 [2] c7 }

  condition:
    any of them
}