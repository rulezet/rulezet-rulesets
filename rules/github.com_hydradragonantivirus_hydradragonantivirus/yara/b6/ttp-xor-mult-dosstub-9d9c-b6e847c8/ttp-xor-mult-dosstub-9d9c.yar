rule TTP_XOR_MULT_DOSStub_9d9c {
  strings:
    $key_9d9c = { c9 f4 [2] bd ec [2] fa ee [2] bd ff [2] f3 f3 [2] ff f9 [2] e8 f2 [2] f3 bc [2] ce }

  condition:
    any of them
}