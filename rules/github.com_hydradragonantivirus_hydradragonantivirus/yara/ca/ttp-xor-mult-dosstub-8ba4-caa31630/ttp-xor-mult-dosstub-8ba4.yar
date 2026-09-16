rule TTP_XOR_MULT_DOSStub_8ba4 {
  strings:
    $key_8ba4 = { df cc [2] ab d4 [2] ec d6 [2] ab c7 [2] e5 cb [2] e9 c1 [2] fe ca [2] e5 84 [2] d8 }

  condition:
    any of them
}