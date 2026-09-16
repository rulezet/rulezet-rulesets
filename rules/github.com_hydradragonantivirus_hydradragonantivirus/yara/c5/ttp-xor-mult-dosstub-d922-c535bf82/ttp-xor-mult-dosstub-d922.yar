rule TTP_XOR_MULT_DOSStub_d922 {
  strings:
    $key_d922 = { 8d 4a [2] f9 52 [2] be 50 [2] f9 41 [2] b7 4d [2] bb 47 [2] ac 4c [2] b7 02 [2] 8a }

  condition:
    any of them
}