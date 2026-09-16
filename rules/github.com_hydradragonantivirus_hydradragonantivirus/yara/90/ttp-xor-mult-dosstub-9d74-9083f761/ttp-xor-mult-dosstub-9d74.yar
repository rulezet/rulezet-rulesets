rule TTP_XOR_MULT_DOSStub_9d74 {
  strings:
    $key_9d74 = { c9 1c [2] bd 04 [2] fa 06 [2] bd 17 [2] f3 1b [2] ff 11 [2] e8 1a [2] f3 54 [2] ce }

  condition:
    any of them
}