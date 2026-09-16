rule TTP_XOR_MULT_DOSStub_9df1 {
  strings:
    $key_9df1 = { c9 99 [2] bd 81 [2] fa 83 [2] bd 92 [2] f3 9e [2] ff 94 [2] e8 9f [2] f3 d1 [2] ce }

  condition:
    any of them
}