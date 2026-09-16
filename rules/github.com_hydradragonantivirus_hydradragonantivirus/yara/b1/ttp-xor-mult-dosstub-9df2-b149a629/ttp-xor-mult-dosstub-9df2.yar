rule TTP_XOR_MULT_DOSStub_9df2 {
  strings:
    $key_9df2 = { c9 9a [2] bd 82 [2] fa 80 [2] bd 91 [2] f3 9d [2] ff 97 [2] e8 9c [2] f3 d2 [2] ce }

  condition:
    any of them
}