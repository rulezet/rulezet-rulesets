rule TTP_XOR_MULT_DOSStub_9dc8 {
  strings:
    $key_9dc8 = { c9 a0 [2] bd b8 [2] fa ba [2] bd ab [2] f3 a7 [2] ff ad [2] e8 a6 [2] f3 e8 [2] ce }

  condition:
    any of them
}