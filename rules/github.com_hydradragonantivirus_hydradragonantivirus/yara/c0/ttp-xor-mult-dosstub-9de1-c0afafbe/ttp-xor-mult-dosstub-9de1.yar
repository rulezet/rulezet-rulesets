rule TTP_XOR_MULT_DOSStub_9de1 {
  strings:
    $key_9de1 = { c9 89 [2] bd 91 [2] fa 93 [2] bd 82 [2] f3 8e [2] ff 84 [2] e8 8f [2] f3 c1 [2] ce }

  condition:
    any of them
}