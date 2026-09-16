rule TTP_XOR_MULT_DOSStub_8b29 {
  strings:
    $key_8b29 = { df 41 [2] ab 59 [2] ec 5b [2] ab 4a [2] e5 46 [2] e9 4c [2] fe 47 [2] e5 09 [2] d8 }

  condition:
    any of them
}