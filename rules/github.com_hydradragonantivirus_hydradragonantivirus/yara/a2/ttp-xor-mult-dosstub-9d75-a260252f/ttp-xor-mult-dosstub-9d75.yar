rule TTP_XOR_MULT_DOSStub_9d75 {
  strings:
    $key_9d75 = { c9 1d [2] bd 05 [2] fa 07 [2] bd 16 [2] f3 1a [2] ff 10 [2] e8 1b [2] f3 55 [2] ce }

  condition:
    any of them
}