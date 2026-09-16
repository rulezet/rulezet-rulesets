rule TTP_XOR_MULT_DOSStub_9ddd {
  strings:
    $key_9ddd = { c9 b5 [2] bd ad [2] fa af [2] bd be [2] f3 b2 [2] ff b8 [2] e8 b3 [2] f3 fd [2] ce }

  condition:
    any of them
}