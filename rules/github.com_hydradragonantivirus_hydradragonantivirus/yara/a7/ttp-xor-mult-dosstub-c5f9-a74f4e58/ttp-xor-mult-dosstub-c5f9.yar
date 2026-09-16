rule TTP_XOR_MULT_DOSStub_c5f9 {
  strings:
    $key_c5f9 = { 91 91 [2] e5 89 [2] a2 8b [2] e5 9a [2] ab 96 [2] a7 9c [2] b0 97 [2] ab d9 [2] 96 }

  condition:
    any of them
}