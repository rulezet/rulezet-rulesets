rule TTP_XOR_MULT_DOSStub_c504 {
  strings:
    $key_c504 = { 91 6c [2] e5 74 [2] a2 76 [2] e5 67 [2] ab 6b [2] a7 61 [2] b0 6a [2] ab 24 [2] 96 }

  condition:
    any of them
}