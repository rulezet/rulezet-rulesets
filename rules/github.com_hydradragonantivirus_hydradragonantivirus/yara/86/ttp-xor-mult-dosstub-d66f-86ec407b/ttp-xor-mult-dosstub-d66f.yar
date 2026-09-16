rule TTP_XOR_MULT_DOSStub_d66f {
  strings:
    $key_d66f = { 82 07 [2] f6 1f [2] b1 1d [2] f6 0c [2] b8 00 [2] b4 0a [2] a3 01 [2] b8 4f [2] 85 }

  condition:
    any of them
}