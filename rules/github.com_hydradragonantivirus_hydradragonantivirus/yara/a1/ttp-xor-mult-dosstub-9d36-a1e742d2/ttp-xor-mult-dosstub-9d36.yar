rule TTP_XOR_MULT_DOSStub_9d36 {
  strings:
    $key_9d36 = { c9 5e [2] bd 46 [2] fa 44 [2] bd 55 [2] f3 59 [2] ff 53 [2] e8 58 [2] f3 16 [2] ce }

  condition:
    any of them
}