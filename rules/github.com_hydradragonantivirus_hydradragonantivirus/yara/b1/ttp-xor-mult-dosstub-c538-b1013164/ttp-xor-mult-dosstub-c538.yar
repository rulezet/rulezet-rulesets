rule TTP_XOR_MULT_DOSStub_c538 {
  strings:
    $key_c538 = { 91 50 [2] e5 48 [2] a2 4a [2] e5 5b [2] ab 57 [2] a7 5d [2] b0 56 [2] ab 18 [2] 96 }

  condition:
    any of them
}