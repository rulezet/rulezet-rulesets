rule TTP_XOR_MULT_DOSStub_9df4 {
  strings:
    $key_9df4 = { c9 9c [2] bd 84 [2] fa 86 [2] bd 97 [2] f3 9b [2] ff 91 [2] e8 9a [2] f3 d4 [2] ce }

  condition:
    any of them
}