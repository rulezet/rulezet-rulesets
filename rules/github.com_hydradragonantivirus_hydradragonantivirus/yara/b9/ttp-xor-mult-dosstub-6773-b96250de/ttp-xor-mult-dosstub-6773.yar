rule TTP_XOR_MULT_DOSStub_6773 {
  strings:
    $key_6773 = { 33 1b [2] 47 03 [2] 00 01 [2] 47 10 [2] 09 1c [2] 05 16 [2] 12 1d [2] 09 53 [2] 34 }

  condition:
    any of them
}