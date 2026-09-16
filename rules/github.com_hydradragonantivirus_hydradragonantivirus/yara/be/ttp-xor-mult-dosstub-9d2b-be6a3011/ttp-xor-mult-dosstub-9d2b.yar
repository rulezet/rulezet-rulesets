rule TTP_XOR_MULT_DOSStub_9d2b {
  strings:
    $key_9d2b = { c9 43 [2] bd 5b [2] fa 59 [2] bd 48 [2] f3 44 [2] ff 4e [2] e8 45 [2] f3 0b [2] ce }

  condition:
    any of them
}