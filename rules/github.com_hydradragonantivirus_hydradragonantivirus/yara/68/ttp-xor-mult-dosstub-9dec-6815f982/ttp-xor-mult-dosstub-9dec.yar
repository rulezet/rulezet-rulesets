rule TTP_XOR_MULT_DOSStub_9dec {
  strings:
    $key_9dec = { c9 84 [2] bd 9c [2] fa 9e [2] bd 8f [2] f3 83 [2] ff 89 [2] e8 82 [2] f3 cc [2] ce }

  condition:
    any of them
}