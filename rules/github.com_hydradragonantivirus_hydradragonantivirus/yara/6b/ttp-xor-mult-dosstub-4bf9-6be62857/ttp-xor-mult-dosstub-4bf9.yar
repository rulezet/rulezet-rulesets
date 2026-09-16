rule TTP_XOR_MULT_DOSStub_4bf9 {
  strings:
    $key_4bf9 = { 1f 91 [2] 6b 89 [2] 2c 8b [2] 6b 9a [2] 25 96 [2] 29 9c [2] 3e 97 [2] 25 d9 [2] 18 }

  condition:
    any of them
}