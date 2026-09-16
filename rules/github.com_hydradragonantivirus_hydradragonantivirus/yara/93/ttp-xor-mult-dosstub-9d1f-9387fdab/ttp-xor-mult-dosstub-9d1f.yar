rule TTP_XOR_MULT_DOSStub_9d1f {
  strings:
    $key_9d1f = { c9 77 [2] bd 6f [2] fa 6d [2] bd 7c [2] f3 70 [2] ff 7a [2] e8 71 [2] f3 3f [2] ce }

  condition:
    any of them
}