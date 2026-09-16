rule TTP_XOR_MULT_DOSStub_c5f2 {
  strings:
    $key_c5f2 = { 91 9a [2] e5 82 [2] a2 80 [2] e5 91 [2] ab 9d [2] a7 97 [2] b0 9c [2] ab d2 [2] 96 }

  condition:
    any of them
}