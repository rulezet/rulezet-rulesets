rule TTP_XOR_MULT_DOSStub_6218 {
  strings:
    $key_6218 = { 36 70 [2] 42 68 [2] 05 6a [2] 42 7b [2] 0c 77 [2] 00 7d [2] 17 76 [2] 0c 38 [2] 31 }

  condition:
    any of them
}