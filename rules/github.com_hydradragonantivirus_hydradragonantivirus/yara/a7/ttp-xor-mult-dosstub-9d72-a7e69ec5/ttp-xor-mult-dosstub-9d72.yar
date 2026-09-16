rule TTP_XOR_MULT_DOSStub_9d72 {
  strings:
    $key_9d72 = { c9 1a [2] bd 02 [2] fa 00 [2] bd 11 [2] f3 1d [2] ff 17 [2] e8 1c [2] f3 52 [2] ce }

  condition:
    any of them
}