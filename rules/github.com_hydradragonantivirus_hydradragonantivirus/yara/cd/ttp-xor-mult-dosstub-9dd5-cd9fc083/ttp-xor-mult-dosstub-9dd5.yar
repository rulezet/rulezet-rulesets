rule TTP_XOR_MULT_DOSStub_9dd5 {
  strings:
    $key_9dd5 = { c9 bd [2] bd a5 [2] fa a7 [2] bd b6 [2] f3 ba [2] ff b0 [2] e8 bb [2] f3 f5 [2] ce }

  condition:
    any of them
}