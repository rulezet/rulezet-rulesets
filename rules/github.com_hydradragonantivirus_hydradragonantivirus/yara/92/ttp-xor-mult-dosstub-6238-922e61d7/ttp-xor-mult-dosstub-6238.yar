rule TTP_XOR_MULT_DOSStub_6238 {
  strings:
    $key_6238 = { 36 50 [2] 42 48 [2] 05 4a [2] 42 5b [2] 0c 57 [2] 00 5d [2] 17 56 [2] 0c 18 [2] 31 }

  condition:
    any of them
}