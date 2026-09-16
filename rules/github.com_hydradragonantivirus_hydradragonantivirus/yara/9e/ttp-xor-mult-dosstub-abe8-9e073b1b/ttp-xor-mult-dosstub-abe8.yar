rule TTP_XOR_MULT_DOSStub_abe8 {
  strings:
    $key_abe8 = { ff 80 [2] 8b 98 [2] cc 9a [2] 8b 8b [2] c5 87 [2] c9 8d [2] de 86 [2] c5 c8 [2] f8 }

  condition:
    any of them
}