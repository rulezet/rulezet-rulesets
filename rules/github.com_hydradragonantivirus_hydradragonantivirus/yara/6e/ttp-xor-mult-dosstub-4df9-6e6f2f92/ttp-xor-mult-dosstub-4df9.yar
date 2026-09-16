rule TTP_XOR_MULT_DOSStub_4df9 {
  strings:
    $key_4df9 = { 19 91 [2] 6d 89 [2] 2a 8b [2] 6d 9a [2] 23 96 [2] 2f 9c [2] 38 97 [2] 23 d9 [2] 1e }

  condition:
    any of them
}