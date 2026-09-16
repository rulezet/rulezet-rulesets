rule TTP_XOR_MULT_DOSStub_44f4 {
  strings:
    $key_44f4 = { 10 9c [2] 64 84 [2] 23 86 [2] 64 97 [2] 2a 9b [2] 26 91 [2] 31 9a [2] 2a d4 [2] 17 }

  condition:
    any of them
}