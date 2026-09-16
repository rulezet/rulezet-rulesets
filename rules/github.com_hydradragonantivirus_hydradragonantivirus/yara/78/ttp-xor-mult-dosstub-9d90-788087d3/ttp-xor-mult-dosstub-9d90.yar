rule TTP_XOR_MULT_DOSStub_9d90 {
  strings:
    $key_9d90 = { c9 f8 [2] bd e0 [2] fa e2 [2] bd f3 [2] f3 ff [2] ff f5 [2] e8 fe [2] f3 b0 [2] ce }

  condition:
    any of them
}