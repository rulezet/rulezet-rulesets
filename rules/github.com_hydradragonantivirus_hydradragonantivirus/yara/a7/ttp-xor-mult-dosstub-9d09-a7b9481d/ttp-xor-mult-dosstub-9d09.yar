rule TTP_XOR_MULT_DOSStub_9d09 {
  strings:
    $key_9d09 = { c9 61 [2] bd 79 [2] fa 7b [2] bd 6a [2] f3 66 [2] ff 6c [2] e8 67 [2] f3 29 [2] ce }

  condition:
    any of them
}