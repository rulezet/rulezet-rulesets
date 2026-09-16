rule TTP_XOR_MULT_DOSStub_8b24 {
  strings:
    $key_8b24 = { df 4c [2] ab 54 [2] ec 56 [2] ab 47 [2] e5 4b [2] e9 41 [2] fe 4a [2] e5 04 [2] d8 }

  condition:
    any of them
}