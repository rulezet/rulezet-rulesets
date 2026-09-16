rule TTP_XOR_MULT_DOSStub_5b38 {
  strings:
    $key_5b38 = { 0f 50 [2] 7b 48 [2] 3c 4a [2] 7b 5b [2] 35 57 [2] 39 5d [2] 2e 56 [2] 35 18 [2] 08 }

  condition:
    any of them
}