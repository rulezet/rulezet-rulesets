rule TTP_XOR_MULT_DOSStub_9d04 {
  strings:
    $key_9d04 = { c9 6c [2] bd 74 [2] fa 76 [2] bd 67 [2] f3 6b [2] ff 61 [2] e8 6a [2] f3 24 [2] ce }

  condition:
    any of them
}