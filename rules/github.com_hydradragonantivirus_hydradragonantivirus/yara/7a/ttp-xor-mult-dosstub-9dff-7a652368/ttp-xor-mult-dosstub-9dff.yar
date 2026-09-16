rule TTP_XOR_MULT_DOSStub_9dff {
  strings:
    $key_9dff = { c9 97 [2] bd 8f [2] fa 8d [2] bd 9c [2] f3 90 [2] ff 9a [2] e8 91 [2] f3 df [2] ce }

  condition:
    any of them
}