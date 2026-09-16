rule TTP_XOR_MULT_DOSStub_9df6 {
  strings:
    $key_9df6 = { c9 9e [2] bd 86 [2] fa 84 [2] bd 95 [2] f3 99 [2] ff 93 [2] e8 98 [2] f3 d6 [2] ce }

  condition:
    any of them
}