rule TTP_XOR_MULT_DOSStub_9d5d {
  strings:
    $key_9d5d = { c9 35 [2] bd 2d [2] fa 2f [2] bd 3e [2] f3 32 [2] ff 38 [2] e8 33 [2] f3 7d [2] ce }

  condition:
    any of them
}