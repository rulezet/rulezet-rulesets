rule TTP_XOR_MULT_DOSStub_e55f {
  strings:
    $key_e55f = { b1 37 [2] c5 2f [2] 82 2d [2] c5 3c [2] 8b 30 [2] 87 3a [2] 90 31 [2] 8b 7f [2] b6 }

  condition:
    any of them
}