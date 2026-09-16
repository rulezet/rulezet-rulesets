rule TTP_XOR_MULT_DOSStub_9dc0 {
  strings:
    $key_9dc0 = { c9 a8 [2] bd b0 [2] fa b2 [2] bd a3 [2] f3 af [2] ff a5 [2] e8 ae [2] f3 e0 [2] ce }

  condition:
    any of them
}