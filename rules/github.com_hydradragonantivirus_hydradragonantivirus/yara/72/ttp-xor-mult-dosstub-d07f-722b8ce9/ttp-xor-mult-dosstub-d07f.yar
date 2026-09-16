rule TTP_XOR_MULT_DOSStub_d07f {
  strings:
    $key_d07f = { 84 17 [2] f0 0f [2] b7 0d [2] f0 1c [2] be 10 [2] b2 1a [2] a5 11 [2] be 5f [2] 83 }

  condition:
    any of them
}