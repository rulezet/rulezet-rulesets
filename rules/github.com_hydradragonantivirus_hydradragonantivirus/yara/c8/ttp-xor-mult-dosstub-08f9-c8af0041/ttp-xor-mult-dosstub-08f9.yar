rule TTP_XOR_MULT_DOSStub_08f9 {
  strings:
    $key_08f9 = { 5c 91 [2] 28 89 [2] 6f 8b [2] 28 9a [2] 66 96 [2] 6a 9c [2] 7d 97 [2] 66 d9 [2] 5b }

  condition:
    any of them
}