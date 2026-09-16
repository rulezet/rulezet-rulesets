rule TTP_XOR_MULT_DOSStub_9d6c {
  strings:
    $key_9d6c = { c9 04 [2] bd 1c [2] fa 1e [2] bd 0f [2] f3 03 [2] ff 09 [2] e8 02 [2] f3 4c [2] ce }

  condition:
    any of them
}