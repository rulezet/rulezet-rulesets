rule TTP_XOR_MULT_DOSStub_8ba3 {
  strings:
    $key_8ba3 = { df cb [2] ab d3 [2] ec d1 [2] ab c0 [2] e5 cc [2] e9 c6 [2] fe cd [2] e5 83 [2] d8 }

  condition:
    any of them
}