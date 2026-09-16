rule TTP_XOR_MULT_DOSStub_8ba6 {
  strings:
    $key_8ba6 = { df ce [2] ab d6 [2] ec d4 [2] ab c5 [2] e5 c9 [2] e9 c3 [2] fe c8 [2] e5 86 [2] d8 }

  condition:
    any of them
}