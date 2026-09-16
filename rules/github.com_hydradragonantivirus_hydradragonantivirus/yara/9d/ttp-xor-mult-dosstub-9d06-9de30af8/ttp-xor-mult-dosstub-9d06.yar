rule TTP_XOR_MULT_DOSStub_9d06 {
  strings:
    $key_9d06 = { c9 6e [2] bd 76 [2] fa 74 [2] bd 65 [2] f3 69 [2] ff 63 [2] e8 68 [2] f3 26 [2] ce }

  condition:
    any of them
}