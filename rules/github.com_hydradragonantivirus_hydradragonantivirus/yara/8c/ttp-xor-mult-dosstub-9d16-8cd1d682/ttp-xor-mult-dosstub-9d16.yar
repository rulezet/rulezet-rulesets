rule TTP_XOR_MULT_DOSStub_9d16 {
  strings:
    $key_9d16 = { c9 7e [2] bd 66 [2] fa 64 [2] bd 75 [2] f3 79 [2] ff 73 [2] e8 78 [2] f3 36 [2] ce }

  condition:
    any of them
}