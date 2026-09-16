rule TTP_XOR_MULT_DOSStub_9da9 {
  strings:
    $key_9da9 = { c9 c1 [2] bd d9 [2] fa db [2] bd ca [2] f3 c6 [2] ff cc [2] e8 c7 [2] f3 89 [2] ce }

  condition:
    any of them
}