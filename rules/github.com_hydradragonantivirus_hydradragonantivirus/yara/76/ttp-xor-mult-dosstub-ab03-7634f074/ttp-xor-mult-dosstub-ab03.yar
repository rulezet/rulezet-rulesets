rule TTP_XOR_MULT_DOSStub_ab03 {
  strings:
    $key_ab03 = { ff 6b [2] 8b 73 [2] cc 71 [2] 8b 60 [2] c5 6c [2] c9 66 [2] de 6d [2] c5 23 [2] f8 }

  condition:
    any of them
}