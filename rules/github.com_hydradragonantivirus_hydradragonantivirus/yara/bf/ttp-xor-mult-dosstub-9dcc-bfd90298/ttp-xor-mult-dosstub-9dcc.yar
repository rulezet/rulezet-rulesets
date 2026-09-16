rule TTP_XOR_MULT_DOSStub_9dcc {
  strings:
    $key_9dcc = { c9 a4 [2] bd bc [2] fa be [2] bd af [2] f3 a3 [2] ff a9 [2] e8 a2 [2] f3 ec [2] ce }

  condition:
    any of them
}