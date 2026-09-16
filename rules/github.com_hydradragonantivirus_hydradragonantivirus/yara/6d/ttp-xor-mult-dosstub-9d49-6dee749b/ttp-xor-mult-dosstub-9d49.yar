rule TTP_XOR_MULT_DOSStub_9d49 {
  strings:
    $key_9d49 = { c9 21 [2] bd 39 [2] fa 3b [2] bd 2a [2] f3 26 [2] ff 2c [2] e8 27 [2] f3 69 [2] ce }

  condition:
    any of them
}