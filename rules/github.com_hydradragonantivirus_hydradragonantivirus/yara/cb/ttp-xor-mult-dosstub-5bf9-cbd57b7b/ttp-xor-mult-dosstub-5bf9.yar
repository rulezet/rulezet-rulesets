rule TTP_XOR_MULT_DOSStub_5bf9 {
  strings:
    $key_5bf9 = { 0f 91 [2] 7b 89 [2] 3c 8b [2] 7b 9a [2] 35 96 [2] 39 9c [2] 2e 97 [2] 35 d9 [2] 08 }

  condition:
    any of them
}