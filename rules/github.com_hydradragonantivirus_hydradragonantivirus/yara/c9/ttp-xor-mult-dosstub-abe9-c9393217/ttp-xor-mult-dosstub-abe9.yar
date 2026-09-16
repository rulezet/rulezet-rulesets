rule TTP_XOR_MULT_DOSStub_abe9 {
  strings:
    $key_abe9 = { ff 81 [2] 8b 99 [2] cc 9b [2] 8b 8a [2] c5 86 [2] c9 8c [2] de 87 [2] c5 c9 [2] f8 }

  condition:
    any of them
}