rule TTP_XOR_MULT_DOSStub_cca6 {
  strings:
    $key_cca6 = { 98 ce [2] ec d6 [2] ab d4 [2] ec c5 [2] a2 c9 [2] ae c3 [2] b9 c8 [2] a2 86 [2] 9f }

  condition:
    any of them
}