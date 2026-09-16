rule TTP_XOR_MULT_DOSStub_8bf3 {
  strings:
    $key_8bf3 = { df 9b [2] ab 83 [2] ec 81 [2] ab 90 [2] e5 9c [2] e9 96 [2] fe 9d [2] e5 d3 [2] d8 }

  condition:
    any of them
}