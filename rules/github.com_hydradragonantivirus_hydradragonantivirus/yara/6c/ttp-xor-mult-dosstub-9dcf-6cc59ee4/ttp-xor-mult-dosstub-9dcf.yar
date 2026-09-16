rule TTP_XOR_MULT_DOSStub_9dcf {
  strings:
    $key_9dcf = { c9 a7 [2] bd bf [2] fa bd [2] bd ac [2] f3 a0 [2] ff aa [2] e8 a1 [2] f3 ef [2] ce }

  condition:
    any of them
}