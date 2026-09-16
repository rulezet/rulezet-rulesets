rule TTP_XOR_MULT_DOSStub_5b02 {
  strings:
    $key_5b02 = { 0f 6a [2] 7b 72 [2] 3c 70 [2] 7b 61 [2] 35 6d [2] 39 67 [2] 2e 6c [2] 35 22 [2] 08 }

  condition:
    any of them
}