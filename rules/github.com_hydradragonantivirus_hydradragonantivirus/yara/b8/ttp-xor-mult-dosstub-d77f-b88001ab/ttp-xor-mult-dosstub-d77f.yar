rule TTP_XOR_MULT_DOSStub_d77f {
  strings:
    $key_d77f = { 83 17 [2] f7 0f [2] b0 0d [2] f7 1c [2] b9 10 [2] b5 1a [2] a2 11 [2] b9 5f [2] 84 }

  condition:
    any of them
}