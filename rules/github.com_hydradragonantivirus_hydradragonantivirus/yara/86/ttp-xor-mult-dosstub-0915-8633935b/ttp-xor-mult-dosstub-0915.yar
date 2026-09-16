rule TTP_XOR_MULT_DOSStub_0915 {
  strings:
    $key_0915 = { 5d 7d [2] 29 65 [2] 6e 67 [2] 29 76 [2] 67 7a [2] 6b 70 [2] 7c 7b [2] 67 35 [2] 5a }

  condition:
    any of them
}