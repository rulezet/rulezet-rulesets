rule TTP_XOR_MULT_DOSStub_6078 {
  strings:
    $key_6078 = { 34 10 [2] 40 08 [2] 07 0a [2] 40 1b [2] 0e 17 [2] 02 1d [2] 15 16 [2] 0e 58 [2] 33 }

  condition:
    any of them
}