rule TTP_XOR_MULT_DOSStub_4cf9 {
  strings:
    $key_4cf9 = { 18 91 [2] 6c 89 [2] 2b 8b [2] 6c 9a [2] 22 96 [2] 2e 9c [2] 39 97 [2] 22 d9 [2] 1f }

  condition:
    any of them
}