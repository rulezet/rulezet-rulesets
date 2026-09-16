rule TTP_XOR_MULT_DOSStub_935a {
  strings:
    $key_935a = { c7 32 [2] b3 2a [2] f4 28 [2] b3 39 [2] fd 35 [2] f1 3f [2] e6 34 [2] fd 7a [2] c0 }

  condition:
    any of them
}