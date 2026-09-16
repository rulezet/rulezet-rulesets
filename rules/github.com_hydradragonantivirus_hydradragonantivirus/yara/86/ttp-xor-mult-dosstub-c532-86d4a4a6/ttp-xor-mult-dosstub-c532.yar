rule TTP_XOR_MULT_DOSStub_c532 {
  strings:
    $key_c532 = { 91 5a [2] e5 42 [2] a2 40 [2] e5 51 [2] ab 5d [2] a7 57 [2] b0 5c [2] ab 12 [2] 96 }

  condition:
    any of them
}