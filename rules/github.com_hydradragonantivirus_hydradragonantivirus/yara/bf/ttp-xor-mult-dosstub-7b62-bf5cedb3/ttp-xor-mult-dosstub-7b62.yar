rule TTP_XOR_MULT_DOSStub_7b62 {
  strings:
    $key_7b62 = { 2f 0a [2] 5b 12 [2] 1c 10 [2] 5b 01 [2] 15 0d [2] 19 07 [2] 0e 0c [2] 15 42 [2] 28 }

  condition:
    any of them
}