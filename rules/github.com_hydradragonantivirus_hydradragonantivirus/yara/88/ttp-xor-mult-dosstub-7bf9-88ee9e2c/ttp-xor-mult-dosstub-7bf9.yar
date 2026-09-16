rule TTP_XOR_MULT_DOSStub_7bf9 {
  strings:
    $key_7bf9 = { 2f 91 [2] 5b 89 [2] 1c 8b [2] 5b 9a [2] 15 96 [2] 19 9c [2] 0e 97 [2] 15 d9 [2] 28 }

  condition:
    any of them
}