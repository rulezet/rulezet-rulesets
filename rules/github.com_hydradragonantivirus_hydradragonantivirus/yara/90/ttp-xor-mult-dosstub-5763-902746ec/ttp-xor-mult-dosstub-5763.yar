rule TTP_XOR_MULT_DOSStub_5763 {
  strings:
    $key_5763 = { 03 0b [2] 77 13 [2] 30 11 [2] 77 00 [2] 39 0c [2] 35 06 [2] 22 0d [2] 39 43 [2] 04 }

  condition:
    any of them
}