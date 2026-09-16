rule TTP_XOR_MULT_DOSStub_9d37 {
  strings:
    $key_9d37 = { c9 5f [2] bd 47 [2] fa 45 [2] bd 54 [2] f3 58 [2] ff 52 [2] e8 59 [2] f3 17 [2] ce }

  condition:
    any of them
}