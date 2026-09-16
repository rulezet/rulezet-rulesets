rule TTP_XOR_MULT_DOSStub_9d0e {
  strings:
    $key_9d0e = { c9 66 [2] bd 7e [2] fa 7c [2] bd 6d [2] f3 61 [2] ff 6b [2] e8 60 [2] f3 2e [2] ce }

  condition:
    any of them
}