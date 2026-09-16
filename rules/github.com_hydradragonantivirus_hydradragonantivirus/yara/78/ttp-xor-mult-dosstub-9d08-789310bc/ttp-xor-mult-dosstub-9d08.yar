rule TTP_XOR_MULT_DOSStub_9d08 {
  strings:
    $key_9d08 = { c9 60 [2] bd 78 [2] fa 7a [2] bd 6b [2] f3 67 [2] ff 6d [2] e8 66 [2] f3 28 [2] ce }

  condition:
    any of them
}