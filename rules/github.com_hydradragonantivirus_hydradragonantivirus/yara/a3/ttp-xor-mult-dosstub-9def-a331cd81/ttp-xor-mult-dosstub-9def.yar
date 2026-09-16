rule TTP_XOR_MULT_DOSStub_9def {
  strings:
    $key_9def = { c9 87 [2] bd 9f [2] fa 9d [2] bd 8c [2] f3 80 [2] ff 8a [2] e8 81 [2] f3 cf [2] ce }

  condition:
    any of them
}