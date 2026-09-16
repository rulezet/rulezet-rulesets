rule TTP_XOR_MULT_DOSStub_9d99 {
  strings:
    $key_9d99 = { c9 f1 [2] bd e9 [2] fa eb [2] bd fa [2] f3 f6 [2] ff fc [2] e8 f7 [2] f3 b9 [2] ce }

  condition:
    any of them
}