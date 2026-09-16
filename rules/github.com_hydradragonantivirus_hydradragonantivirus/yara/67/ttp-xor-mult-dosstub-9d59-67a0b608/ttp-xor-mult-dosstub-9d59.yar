rule TTP_XOR_MULT_DOSStub_9d59 {
  strings:
    $key_9d59 = { c9 31 [2] bd 29 [2] fa 2b [2] bd 3a [2] f3 36 [2] ff 3c [2] e8 37 [2] f3 79 [2] ce }

  condition:
    any of them
}