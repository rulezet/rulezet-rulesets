rule TTP_XOR_MULT_DOSStub_8b6a {
  strings:
    $key_8b6a = { df 02 [2] ab 1a [2] ec 18 [2] ab 09 [2] e5 05 [2] e9 0f [2] fe 04 [2] e5 4a [2] d8 }

  condition:
    any of them
}