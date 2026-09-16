rule TTP_XOR_MULT_DOSStub_9d5f {
  strings:
    $key_9d5f = { c9 37 [2] bd 2f [2] fa 2d [2] bd 3c [2] f3 30 [2] ff 3a [2] e8 31 [2] f3 7f [2] ce }

  condition:
    any of them
}