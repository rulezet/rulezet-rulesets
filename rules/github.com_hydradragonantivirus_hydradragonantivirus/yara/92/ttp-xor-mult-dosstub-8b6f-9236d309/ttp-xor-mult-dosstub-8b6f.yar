rule TTP_XOR_MULT_DOSStub_8b6f {
  strings:
    $key_8b6f = { df 07 [2] ab 1f [2] ec 1d [2] ab 0c [2] e5 00 [2] e9 0a [2] fe 01 [2] e5 4f [2] d8 }

  condition:
    any of them
}