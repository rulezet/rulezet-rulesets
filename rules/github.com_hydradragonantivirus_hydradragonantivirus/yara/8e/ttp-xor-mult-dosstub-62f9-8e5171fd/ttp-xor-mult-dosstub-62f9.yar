rule TTP_XOR_MULT_DOSStub_62f9 {
  strings:
    $key_62f9 = { 36 91 [2] 42 89 [2] 05 8b [2] 42 9a [2] 0c 96 [2] 00 9c [2] 17 97 [2] 0c d9 [2] 31 }

  condition:
    any of them
}