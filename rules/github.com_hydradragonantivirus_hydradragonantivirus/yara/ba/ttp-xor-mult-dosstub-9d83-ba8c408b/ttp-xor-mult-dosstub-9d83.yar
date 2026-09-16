rule TTP_XOR_MULT_DOSStub_9d83 {
  strings:
    $key_9d83 = { c9 eb [2] bd f3 [2] fa f1 [2] bd e0 [2] f3 ec [2] ff e6 [2] e8 ed [2] f3 a3 [2] ce }

  condition:
    any of them
}