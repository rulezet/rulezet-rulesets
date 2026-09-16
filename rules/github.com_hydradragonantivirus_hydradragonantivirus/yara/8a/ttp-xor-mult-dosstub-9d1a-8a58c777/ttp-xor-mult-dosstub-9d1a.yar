rule TTP_XOR_MULT_DOSStub_9d1a {
  strings:
    $key_9d1a = { c9 72 [2] bd 6a [2] fa 68 [2] bd 79 [2] f3 75 [2] ff 7f [2] e8 74 [2] f3 3a [2] ce }

  condition:
    any of them
}