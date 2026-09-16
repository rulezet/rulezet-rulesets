rule TTP_XOR_MULT_DOSStub_9d80 {
  strings:
    $key_9d80 = { c9 e8 [2] bd f0 [2] fa f2 [2] bd e3 [2] f3 ef [2] ff e5 [2] e8 ee [2] f3 a0 [2] ce }

  condition:
    any of them
}