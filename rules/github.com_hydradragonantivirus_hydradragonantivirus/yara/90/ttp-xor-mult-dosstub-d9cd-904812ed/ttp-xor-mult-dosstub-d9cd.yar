rule TTP_XOR_MULT_DOSStub_d9cd {
  strings:
    $key_d9cd = { 8d a5 [2] f9 bd [2] be bf [2] f9 ae [2] b7 a2 [2] bb a8 [2] ac a3 [2] b7 ed [2] 8a }

  condition:
    any of them
}