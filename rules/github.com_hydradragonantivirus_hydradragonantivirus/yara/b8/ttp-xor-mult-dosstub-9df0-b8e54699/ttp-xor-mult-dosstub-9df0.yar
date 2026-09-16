rule TTP_XOR_MULT_DOSStub_9df0 {
  strings:
    $key_9df0 = { c9 98 [2] bd 80 [2] fa 82 [2] bd 93 [2] f3 9f [2] ff 95 [2] e8 9e [2] f3 d0 [2] ce }

  condition:
    any of them
}