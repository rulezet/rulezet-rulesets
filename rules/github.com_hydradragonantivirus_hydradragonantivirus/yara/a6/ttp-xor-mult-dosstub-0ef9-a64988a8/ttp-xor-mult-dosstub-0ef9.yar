rule TTP_XOR_MULT_DOSStub_0ef9 {
  strings:
    $key_0ef9 = { 5a 91 [2] 2e 89 [2] 69 8b [2] 2e 9a [2] 60 96 [2] 6c 9c [2] 7b 97 [2] 60 d9 [2] 5d }

  condition:
    any of them
}