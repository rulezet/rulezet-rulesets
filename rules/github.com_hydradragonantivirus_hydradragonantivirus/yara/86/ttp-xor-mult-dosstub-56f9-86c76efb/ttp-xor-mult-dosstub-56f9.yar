rule TTP_XOR_MULT_DOSStub_56f9 {
  strings:
    $key_56f9 = { 02 91 [2] 76 89 [2] 31 8b [2] 76 9a [2] 38 96 [2] 34 9c [2] 23 97 [2] 38 d9 [2] 05 }

  condition:
    any of them
}