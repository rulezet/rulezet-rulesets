rule TTP_XOR_MULT_DOSStub_9d20 {
  strings:
    $key_9d20 = { c9 48 [2] bd 50 [2] fa 52 [2] bd 43 [2] f3 4f [2] ff 45 [2] e8 4e [2] f3 00 [2] ce }

  condition:
    any of them
}