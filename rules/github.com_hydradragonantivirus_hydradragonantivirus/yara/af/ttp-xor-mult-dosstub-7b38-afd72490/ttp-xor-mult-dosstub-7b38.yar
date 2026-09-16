rule TTP_XOR_MULT_DOSStub_7b38 {
  strings:
    $key_7b38 = { 2f 50 [2] 5b 48 [2] 1c 4a [2] 5b 5b [2] 15 57 [2] 19 5d [2] 0e 56 [2] 15 18 [2] 28 }

  condition:
    any of them
}