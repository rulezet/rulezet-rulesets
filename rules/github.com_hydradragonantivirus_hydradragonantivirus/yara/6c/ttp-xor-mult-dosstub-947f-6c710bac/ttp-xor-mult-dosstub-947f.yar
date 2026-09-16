rule TTP_XOR_MULT_DOSStub_947f {
  strings:
    $key_947f = { c0 17 [2] b4 0f [2] f3 0d [2] b4 1c [2] fa 10 [2] f6 1a [2] e1 11 [2] fa 5f [2] c7 }

  condition:
    any of them
}