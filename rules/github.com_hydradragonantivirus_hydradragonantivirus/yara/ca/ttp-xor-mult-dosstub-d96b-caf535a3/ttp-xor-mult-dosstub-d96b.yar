rule TTP_XOR_MULT_DOSStub_d96b {
  strings:
    $key_d96b = { 8d 03 [2] f9 1b [2] be 19 [2] f9 08 [2] b7 04 [2] bb 0e [2] ac 05 [2] b7 4b [2] 8a }

  condition:
    any of them
}