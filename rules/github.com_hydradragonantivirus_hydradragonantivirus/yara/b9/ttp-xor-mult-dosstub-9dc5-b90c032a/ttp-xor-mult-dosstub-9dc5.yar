rule TTP_XOR_MULT_DOSStub_9dc5 {
  strings:
    $key_9dc5 = { c9 ad [2] bd b5 [2] fa b7 [2] bd a6 [2] f3 aa [2] ff a0 [2] e8 ab [2] f3 e5 [2] ce }

  condition:
    any of them
}