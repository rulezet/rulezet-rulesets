rule TTP_XOR_MULT_DOSStub_9d6b {
  strings:
    $key_9d6b = { c9 03 [2] bd 1b [2] fa 19 [2] bd 08 [2] f3 04 [2] ff 0e [2] e8 05 [2] f3 4b [2] ce }

  condition:
    any of them
}