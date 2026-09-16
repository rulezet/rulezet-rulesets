rule TTP_XOR_MULT_DOSStub_d9f2 {
  strings:
    $key_d9f2 = { 8d 9a [2] f9 82 [2] be 80 [2] f9 91 [2] b7 9d [2] bb 97 [2] ac 9c [2] b7 d2 [2] 8a }

  condition:
    any of them
}