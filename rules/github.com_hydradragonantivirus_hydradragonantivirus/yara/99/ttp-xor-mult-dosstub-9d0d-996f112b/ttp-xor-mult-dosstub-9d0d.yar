rule TTP_XOR_MULT_DOSStub_9d0d {
  strings:
    $key_9d0d = { c9 65 [2] bd 7d [2] fa 7f [2] bd 6e [2] f3 62 [2] ff 68 [2] e8 63 [2] f3 2d [2] ce }

  condition:
    any of them
}