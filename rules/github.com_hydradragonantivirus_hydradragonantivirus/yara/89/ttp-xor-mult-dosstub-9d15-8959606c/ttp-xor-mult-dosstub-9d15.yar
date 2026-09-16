rule TTP_XOR_MULT_DOSStub_9d15 {
  strings:
    $key_9d15 = { c9 7d [2] bd 65 [2] fa 67 [2] bd 76 [2] f3 7a [2] ff 70 [2] e8 7b [2] f3 35 [2] ce }

  condition:
    any of them
}