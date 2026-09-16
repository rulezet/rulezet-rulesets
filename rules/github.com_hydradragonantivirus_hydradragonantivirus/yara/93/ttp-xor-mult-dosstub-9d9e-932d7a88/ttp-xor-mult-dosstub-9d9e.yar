rule TTP_XOR_MULT_DOSStub_9d9e {
  strings:
    $key_9d9e = { c9 f6 [2] bd ee [2] fa ec [2] bd fd [2] f3 f1 [2] ff fb [2] e8 f0 [2] f3 be [2] ce }

  condition:
    any of them
}