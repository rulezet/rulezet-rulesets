rule TTP_XOR_MULT_DOSStub_9dc4 {
  strings:
    $key_9dc4 = { c9 ac [2] bd b4 [2] fa b6 [2] bd a7 [2] f3 ab [2] ff a1 [2] e8 aa [2] f3 e4 [2] ce }

  condition:
    any of them
}