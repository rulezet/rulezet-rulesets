rule TTP_XOR_MULT_DOSStub_9d26 {
  strings:
    $key_9d26 = { c9 4e [2] bd 56 [2] fa 54 [2] bd 45 [2] f3 49 [2] ff 43 [2] e8 48 [2] f3 06 [2] ce }

  condition:
    any of them
}