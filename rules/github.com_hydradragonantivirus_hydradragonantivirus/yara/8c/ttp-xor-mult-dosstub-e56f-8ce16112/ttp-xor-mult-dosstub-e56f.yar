rule TTP_XOR_MULT_DOSStub_e56f {
  strings:
    $key_e56f = { b1 07 [2] c5 1f [2] 82 1d [2] c5 0c [2] 8b 00 [2] 87 0a [2] 90 01 [2] 8b 4f [2] b6 }

  condition:
    any of them
}