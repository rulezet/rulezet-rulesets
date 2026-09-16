rule TTP_XOR_MULT_DOSStub_9d84 {
  strings:
    $key_9d84 = { c9 ec [2] bd f4 [2] fa f6 [2] bd e7 [2] f3 eb [2] ff e1 [2] e8 ea [2] f3 a4 [2] ce }

  condition:
    any of them
}