rule TTP_XOR_MULT_DOSStub_d91b {
  strings:
    $key_d91b = { 8d 73 [2] f9 6b [2] be 69 [2] f9 78 [2] b7 74 [2] bb 7e [2] ac 75 [2] b7 3b [2] 8a }

  condition:
    any of them
}