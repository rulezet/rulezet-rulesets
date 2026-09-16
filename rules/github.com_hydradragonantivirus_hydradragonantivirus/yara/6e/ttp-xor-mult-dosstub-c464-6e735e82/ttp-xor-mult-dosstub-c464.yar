rule TTP_XOR_MULT_DOSStub_c464 {
  strings:
    $key_c464 = { 90 0c [2] e4 14 [2] a3 16 [2] e4 07 [2] aa 0b [2] a6 01 [2] b1 0a [2] aa 44 [2] 97 }

  condition:
    any of them
}