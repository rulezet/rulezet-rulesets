rule TTP_XOR_MULT_DOSStub_9dc2 {
  strings:
    $key_9dc2 = { c9 aa [2] bd b2 [2] fa b0 [2] bd a1 [2] f3 ad [2] ff a7 [2] e8 ac [2] f3 e2 [2] ce }

  condition:
    any of them
}