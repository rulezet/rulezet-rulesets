rule TTP_XOR_MULT_DOSStub_c5e8 {
  strings:
    $key_c5e8 = { 91 80 [2] e5 98 [2] a2 9a [2] e5 8b [2] ab 87 [2] a7 8d [2] b0 86 [2] ab c8 [2] 96 }

  condition:
    any of them
}