rule TTP_XOR_MULT_DOSStub_44f9 {
  strings:
    $key_44f9 = { 10 91 [2] 64 89 [2] 23 8b [2] 64 9a [2] 2a 96 [2] 26 9c [2] 31 97 [2] 2a d9 [2] 17 }

  condition:
    any of them
}