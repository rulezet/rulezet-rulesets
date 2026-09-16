rule TTP_XOR_MULT_DOSStub_9daa {
  strings:
    $key_9daa = { c9 c2 [2] bd da [2] fa d8 [2] bd c9 [2] f3 c5 [2] ff cf [2] e8 c4 [2] f3 8a [2] ce }

  condition:
    any of them
}