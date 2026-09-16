rule TTP_XOR_MULT_DOSStub_9dd6 {
  strings:
    $key_9dd6 = { c9 be [2] bd a6 [2] fa a4 [2] bd b5 [2] f3 b9 [2] ff b3 [2] e8 b8 [2] f3 f6 [2] ce }

  condition:
    any of them
}