rule TTP_XOR_MULT_DOSStub_d955 {
  strings:
    $key_d955 = { 8d 3d [2] f9 25 [2] be 27 [2] f9 36 [2] b7 3a [2] bb 30 [2] ac 3b [2] b7 75 [2] 8a }

  condition:
    any of them
}