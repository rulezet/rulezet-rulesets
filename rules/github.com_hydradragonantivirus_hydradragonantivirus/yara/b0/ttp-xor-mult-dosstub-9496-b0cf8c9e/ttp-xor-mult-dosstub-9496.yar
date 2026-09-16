rule TTP_XOR_MULT_DOSStub_9496 {
  strings:
    $key_9496 = { c0 fe [2] b4 e6 [2] f3 e4 [2] b4 f5 [2] fa f9 [2] f6 f3 [2] e1 f8 [2] fa b6 [2] c7 }

  condition:
    any of them
}