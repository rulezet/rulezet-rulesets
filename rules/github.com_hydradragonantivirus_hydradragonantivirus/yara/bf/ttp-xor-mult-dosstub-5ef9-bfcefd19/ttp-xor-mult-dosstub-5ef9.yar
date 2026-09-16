rule TTP_XOR_MULT_DOSStub_5ef9 {
  strings:
    $key_5ef9 = { 0a 91 [2] 7e 89 [2] 39 8b [2] 7e 9a [2] 30 96 [2] 3c 9c [2] 2b 97 [2] 30 d9 [2] 0d }

  condition:
    any of them
}