rule TTP_XOR_MULT_DOSStub_d9fa {
  strings:
    $key_d9fa = { 8d 92 [2] f9 8a [2] be 88 [2] f9 99 [2] b7 95 [2] bb 9f [2] ac 94 [2] b7 da [2] 8a }

  condition:
    any of them
}