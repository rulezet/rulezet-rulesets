rule TTP_XOR_MULT_DOSStub_9dd3 {
  strings:
    $key_9dd3 = { c9 bb [2] bd a3 [2] fa a1 [2] bd b0 [2] f3 bc [2] ff b6 [2] e8 bd [2] f3 f3 [2] ce }

  condition:
    any of them
}