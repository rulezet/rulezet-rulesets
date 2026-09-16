rule TTP_XOR_MULT_DOSStub_0934 {
  strings:
    $key_0934 = { 5d 5c [2] 29 44 [2] 6e 46 [2] 29 57 [2] 67 5b [2] 6b 51 [2] 7c 5a [2] 67 14 [2] 5a }

  condition:
    any of them
}