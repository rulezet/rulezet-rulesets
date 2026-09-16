rule TTP_XOR_MULT_DOSStub_8beb {
  strings:
    $key_8beb = { df 83 [2] ab 9b [2] ec 99 [2] ab 88 [2] e5 84 [2] e9 8e [2] fe 85 [2] e5 cb [2] d8 }

  condition:
    any of them
}