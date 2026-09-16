rule TTP_XOR_MULT_DOSStub_9d32 {
  strings:
    $key_9d32 = { c9 5a [2] bd 42 [2] fa 40 [2] bd 51 [2] f3 5d [2] ff 57 [2] e8 5c [2] f3 12 [2] ce }

  condition:
    any of them
}