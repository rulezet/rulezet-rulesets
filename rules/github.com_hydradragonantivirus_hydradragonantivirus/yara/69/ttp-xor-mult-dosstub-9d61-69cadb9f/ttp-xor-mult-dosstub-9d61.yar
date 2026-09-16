rule TTP_XOR_MULT_DOSStub_9d61 {
  strings:
    $key_9d61 = { c9 09 [2] bd 11 [2] fa 13 [2] bd 02 [2] f3 0e [2] ff 04 [2] e8 0f [2] f3 41 [2] ce }

  condition:
    any of them
}