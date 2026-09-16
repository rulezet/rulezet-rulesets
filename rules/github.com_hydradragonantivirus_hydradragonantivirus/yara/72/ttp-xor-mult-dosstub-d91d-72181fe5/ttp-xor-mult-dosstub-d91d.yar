rule TTP_XOR_MULT_DOSStub_d91d {
  strings:
    $key_d91d = { 8d 75 [2] f9 6d [2] be 6f [2] f9 7e [2] b7 72 [2] bb 78 [2] ac 73 [2] b7 3d [2] 8a }

  condition:
    any of them
}