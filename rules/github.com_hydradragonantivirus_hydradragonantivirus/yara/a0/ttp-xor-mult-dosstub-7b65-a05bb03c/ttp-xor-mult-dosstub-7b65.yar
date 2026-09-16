rule TTP_XOR_MULT_DOSStub_7b65 {
  strings:
    $key_7b65 = { 2f 0d [2] 5b 15 [2] 1c 17 [2] 5b 06 [2] 15 0a [2] 19 00 [2] 0e 0b [2] 15 45 [2] 28 }

  condition:
    any of them
}