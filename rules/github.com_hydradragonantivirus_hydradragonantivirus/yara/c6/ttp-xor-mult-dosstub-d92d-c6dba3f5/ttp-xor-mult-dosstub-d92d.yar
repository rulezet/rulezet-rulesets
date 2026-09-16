rule TTP_XOR_MULT_DOSStub_d92d {
  strings:
    $key_d92d = { 8d 45 [2] f9 5d [2] be 5f [2] f9 4e [2] b7 42 [2] bb 48 [2] ac 43 [2] b7 0d [2] 8a }

  condition:
    any of them
}