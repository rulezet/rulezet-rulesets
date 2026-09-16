rule TTP_XOR_MULT_DOSStub_0b18 {
  strings:
    $key_0b18 = { 5f 70 [2] 2b 68 [2] 6c 6a [2] 2b 7b [2] 65 77 [2] 69 7d [2] 7e 76 [2] 65 38 [2] 58 }

  condition:
    any of them
}