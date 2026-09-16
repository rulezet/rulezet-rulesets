rule TTP_XOR_MULT_DOSStub_9d87 {
  strings:
    $key_9d87 = { c9 ef [2] bd f7 [2] fa f5 [2] bd e4 [2] f3 e8 [2] ff e2 [2] e8 e9 [2] f3 a7 [2] ce }

  condition:
    any of them
}