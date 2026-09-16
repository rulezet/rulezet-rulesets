rule TTP_XOR_MULT_DOSStub_d944 {
  strings:
    $key_d944 = { 8d 2c [2] f9 34 [2] be 36 [2] f9 27 [2] b7 2b [2] bb 21 [2] ac 2a [2] b7 64 [2] 8a }

  condition:
    any of them
}