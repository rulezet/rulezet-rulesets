rule TTP_XOR_MULT_DOSStub_9d7d {
  strings:
    $key_9d7d = { c9 15 [2] bd 0d [2] fa 0f [2] bd 1e [2] f3 12 [2] ff 18 [2] e8 13 [2] f3 5d [2] ce }

  condition:
    any of them
}