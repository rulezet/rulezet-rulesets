rule TTP_XOR_MULT_DOSStub_9d7f {
  strings:
    $key_9d7f = { c9 17 [2] bd 0f [2] fa 0d [2] bd 1c [2] f3 10 [2] ff 1a [2] e8 11 [2] f3 5f [2] ce }

  condition:
    any of them
}