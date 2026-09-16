rule TTP_XOR_MULT_DOSStub_9d51 {
  strings:
    $key_9d51 = { c9 39 [2] bd 21 [2] fa 23 [2] bd 32 [2] f3 3e [2] ff 34 [2] e8 3f [2] f3 71 [2] ce }

  condition:
    any of them
}