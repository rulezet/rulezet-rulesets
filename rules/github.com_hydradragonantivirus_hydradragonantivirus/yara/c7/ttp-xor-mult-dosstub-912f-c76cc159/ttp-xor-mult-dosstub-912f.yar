rule TTP_XOR_MULT_DOSStub_912f {
  strings:
    $key_912f = { c5 47 [2] b1 5f [2] f6 5d [2] b1 4c [2] ff 40 [2] f3 4a [2] e4 41 [2] ff 0f [2] c2 }

  condition:
    any of them
}