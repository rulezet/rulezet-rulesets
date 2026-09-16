rule TTP_XOR_MULT_DOSStub_9d64 {
  strings:
    $key_9d64 = { c9 0c [2] bd 14 [2] fa 16 [2] bd 07 [2] f3 0b [2] ff 01 [2] e8 0a [2] f3 44 [2] ce }

  condition:
    any of them
}