rule TTP_XOR_MULT_DOSStub_9d4d {
  strings:
    $key_9d4d = { c9 25 [2] bd 3d [2] fa 3f [2] bd 2e [2] f3 22 [2] ff 28 [2] e8 23 [2] f3 6d [2] ce }

  condition:
    any of them
}