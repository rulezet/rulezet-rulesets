rule TTP_XOR_MULT_DOSStub_8b04 {
  strings:
    $key_8b04 = { df 6c [2] ab 74 [2] ec 76 [2] ab 67 [2] e5 6b [2] e9 61 [2] fe 6a [2] e5 24 [2] d8 }

  condition:
    any of them
}