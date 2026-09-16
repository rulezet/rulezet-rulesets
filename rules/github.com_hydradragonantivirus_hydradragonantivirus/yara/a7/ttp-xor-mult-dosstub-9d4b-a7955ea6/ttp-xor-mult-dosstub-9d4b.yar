rule TTP_XOR_MULT_DOSStub_9d4b {
  strings:
    $key_9d4b = { c9 23 [2] bd 3b [2] fa 39 [2] bd 28 [2] f3 24 [2] ff 2e [2] e8 25 [2] f3 6b [2] ce }

  condition:
    any of them
}