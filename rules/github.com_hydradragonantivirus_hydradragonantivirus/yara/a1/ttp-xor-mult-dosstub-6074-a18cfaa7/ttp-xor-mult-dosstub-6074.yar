rule TTP_XOR_MULT_DOSStub_6074 {
  strings:
    $key_6074 = { 34 1c [2] 40 04 [2] 07 06 [2] 40 17 [2] 0e 1b [2] 02 11 [2] 15 1a [2] 0e 54 [2] 33 }

  condition:
    any of them
}