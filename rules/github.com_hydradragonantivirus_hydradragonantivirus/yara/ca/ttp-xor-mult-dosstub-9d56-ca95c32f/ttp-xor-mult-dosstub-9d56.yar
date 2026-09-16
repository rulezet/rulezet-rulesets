rule TTP_XOR_MULT_DOSStub_9d56 {
  strings:
    $key_9d56 = { c9 3e [2] bd 26 [2] fa 24 [2] bd 35 [2] f3 39 [2] ff 33 [2] e8 38 [2] f3 76 [2] ce }

  condition:
    any of them
}