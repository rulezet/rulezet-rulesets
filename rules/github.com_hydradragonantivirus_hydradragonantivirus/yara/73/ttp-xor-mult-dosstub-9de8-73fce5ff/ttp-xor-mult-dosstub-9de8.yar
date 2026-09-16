rule TTP_XOR_MULT_DOSStub_9de8 {
  strings:
    $key_9de8 = { c9 80 [2] bd 98 [2] fa 9a [2] bd 8b [2] f3 87 [2] ff 8d [2] e8 86 [2] f3 c8 [2] ce }

  condition:
    any of them
}