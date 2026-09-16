rule TTP_XOR_MULT_DOSStub_946a {
  strings:
    $key_946a = { c0 02 [2] b4 1a [2] f3 18 [2] b4 09 [2] fa 05 [2] f6 0f [2] e1 04 [2] fa 4a [2] c7 }

  condition:
    any of them
}