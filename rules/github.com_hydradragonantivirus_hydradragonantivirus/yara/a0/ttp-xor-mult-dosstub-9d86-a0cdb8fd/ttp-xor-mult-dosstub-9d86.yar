rule TTP_XOR_MULT_DOSStub_9d86 {
  strings:
    $key_9d86 = { c9 ee [2] bd f6 [2] fa f4 [2] bd e5 [2] f3 e9 [2] ff e3 [2] e8 e8 [2] f3 a6 [2] ce }

  condition:
    any of them
}