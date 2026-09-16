rule TTP_XOR_MULT_DOSStub_7bf4 {
  strings:
    $key_7bf4 = { 2f 9c [2] 5b 84 [2] 1c 86 [2] 5b 97 [2] 15 9b [2] 19 91 [2] 0e 9a [2] 15 d4 [2] 28 }

  condition:
    any of them
}