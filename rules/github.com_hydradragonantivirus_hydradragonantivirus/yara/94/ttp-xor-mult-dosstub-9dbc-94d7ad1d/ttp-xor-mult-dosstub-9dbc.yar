rule TTP_XOR_MULT_DOSStub_9dbc {
  strings:
    $key_9dbc = { c9 d4 [2] bd cc [2] fa ce [2] bd df [2] f3 d3 [2] ff d9 [2] e8 d2 [2] f3 9c [2] ce }

  condition:
    any of them
}