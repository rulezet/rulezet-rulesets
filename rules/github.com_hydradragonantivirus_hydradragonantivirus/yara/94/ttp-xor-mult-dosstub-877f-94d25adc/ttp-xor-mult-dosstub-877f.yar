rule TTP_XOR_MULT_DOSStub_877f {
  strings:
    $key_877f = { d3 17 [2] a7 0f [2] e0 0d [2] a7 1c [2] e9 10 [2] e5 1a [2] f2 11 [2] e9 5f [2] d4 }

  condition:
    any of them
}