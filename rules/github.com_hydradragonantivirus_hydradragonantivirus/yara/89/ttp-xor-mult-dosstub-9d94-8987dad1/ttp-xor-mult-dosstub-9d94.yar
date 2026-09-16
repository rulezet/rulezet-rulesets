rule TTP_XOR_MULT_DOSStub_9d94 {
  strings:
    $key_9d94 = { c9 fc [2] bd e4 [2] fa e6 [2] bd f7 [2] f3 fb [2] ff f1 [2] e8 fa [2] f3 b4 [2] ce }

  condition:
    any of them
}