rule TTP_XOR_MULT_DOSStub_9d76 {
  strings:
    $key_9d76 = { c9 1e [2] bd 06 [2] fa 04 [2] bd 15 [2] f3 19 [2] ff 13 [2] e8 18 [2] f3 56 [2] ce }

  condition:
    any of them
}