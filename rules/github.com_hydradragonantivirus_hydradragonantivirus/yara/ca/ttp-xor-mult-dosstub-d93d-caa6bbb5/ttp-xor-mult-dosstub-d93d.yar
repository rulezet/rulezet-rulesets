rule TTP_XOR_MULT_DOSStub_d93d {
  strings:
    $key_d93d = { 8d 55 [2] f9 4d [2] be 4f [2] f9 5e [2] b7 52 [2] bb 58 [2] ac 53 [2] b7 1d [2] 8a }

  condition:
    any of them
}