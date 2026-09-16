rule TTP_XOR_MULT_DOSStub_937f {
  strings:
    $key_937f = { c7 17 [2] b3 0f [2] f4 0d [2] b3 1c [2] fd 10 [2] f1 1a [2] e6 11 [2] fd 5f [2] c0 }

  condition:
    any of them
}