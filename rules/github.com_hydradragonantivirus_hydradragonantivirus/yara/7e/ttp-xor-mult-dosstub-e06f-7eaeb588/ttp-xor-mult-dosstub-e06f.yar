rule TTP_XOR_MULT_DOSStub_e06f {
  strings:
    $key_e06f = { b4 07 [2] c0 1f [2] 87 1d [2] c0 0c [2] 8e 00 [2] 82 0a [2] 95 01 [2] 8e 4f [2] b3 }

  condition:
    any of them
}