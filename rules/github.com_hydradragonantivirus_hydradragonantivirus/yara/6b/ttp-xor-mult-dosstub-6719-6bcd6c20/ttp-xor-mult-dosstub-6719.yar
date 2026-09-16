rule TTP_XOR_MULT_DOSStub_6719 {
  strings:
    $key_6719 = { 33 71 [2] 47 69 [2] 00 6b [2] 47 7a [2] 09 76 [2] 05 7c [2] 12 77 [2] 09 39 [2] 34 }

  condition:
    any of them
}