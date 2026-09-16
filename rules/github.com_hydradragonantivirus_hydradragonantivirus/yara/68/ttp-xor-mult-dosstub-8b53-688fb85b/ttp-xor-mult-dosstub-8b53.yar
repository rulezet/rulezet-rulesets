rule TTP_XOR_MULT_DOSStub_8b53 {
  strings:
    $key_8b53 = { df 3b [2] ab 23 [2] ec 21 [2] ab 30 [2] e5 3c [2] e9 36 [2] fe 3d [2] e5 73 [2] d8 }

  condition:
    any of them
}