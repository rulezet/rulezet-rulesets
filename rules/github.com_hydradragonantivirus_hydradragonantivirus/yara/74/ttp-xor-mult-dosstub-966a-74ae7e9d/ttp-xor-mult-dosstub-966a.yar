rule TTP_XOR_MULT_DOSStub_966a {
  strings:
    $key_966a = { c2 02 [2] b6 1a [2] f1 18 [2] b6 09 [2] f8 05 [2] f4 0f [2] e3 04 [2] f8 4a [2] c5 }

  condition:
    any of them
}