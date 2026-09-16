rule TTP_XOR_MULT_DOSStub_9dd9 {
  strings:
    $key_9dd9 = { c9 b1 [2] bd a9 [2] fa ab [2] bd ba [2] f3 b6 [2] ff bc [2] e8 b7 [2] f3 f9 [2] ce }

  condition:
    any of them
}