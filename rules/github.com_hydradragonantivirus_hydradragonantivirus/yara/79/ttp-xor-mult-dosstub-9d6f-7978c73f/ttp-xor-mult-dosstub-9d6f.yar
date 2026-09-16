rule TTP_XOR_MULT_DOSStub_9d6f {
  strings:
    $key_9d6f = { c9 07 [2] bd 1f [2] fa 1d [2] bd 0c [2] f3 00 [2] ff 0a [2] e8 01 [2] f3 4f [2] ce }

  condition:
    any of them
}