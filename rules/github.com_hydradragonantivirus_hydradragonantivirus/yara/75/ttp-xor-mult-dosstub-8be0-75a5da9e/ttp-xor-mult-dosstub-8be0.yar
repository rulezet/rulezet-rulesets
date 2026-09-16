rule TTP_XOR_MULT_DOSStub_8be0 {
  strings:
    $key_8be0 = { df 88 [2] ab 90 [2] ec 92 [2] ab 83 [2] e5 8f [2] e9 85 [2] fe 8e [2] e5 c0 [2] d8 }

  condition:
    any of them
}