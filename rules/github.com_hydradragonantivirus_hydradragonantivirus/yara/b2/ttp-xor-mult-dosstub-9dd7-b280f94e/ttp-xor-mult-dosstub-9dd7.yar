rule TTP_XOR_MULT_DOSStub_9dd7 {
  strings:
    $key_9dd7 = { c9 bf [2] bd a7 [2] fa a5 [2] bd b4 [2] f3 b8 [2] ff b2 [2] e8 b9 [2] f3 f7 [2] ce }

  condition:
    any of them
}