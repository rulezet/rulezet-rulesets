rule TTP_XOR_MULT_DOSStub_0be5 {
  strings:
    $key_0be5 = { 5f 8d [2] 2b 95 [2] 6c 97 [2] 2b 86 [2] 65 8a [2] 69 80 [2] 7e 8b [2] 65 c5 [2] 58 }

  condition:
    any of them
}