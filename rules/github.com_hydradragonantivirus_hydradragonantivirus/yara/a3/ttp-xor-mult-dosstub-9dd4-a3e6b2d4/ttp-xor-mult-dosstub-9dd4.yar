rule TTP_XOR_MULT_DOSStub_9dd4 {
  strings:
    $key_9dd4 = { c9 bc [2] bd a4 [2] fa a6 [2] bd b7 [2] f3 bb [2] ff b1 [2] e8 ba [2] f3 f4 [2] ce }

  condition:
    any of them
}