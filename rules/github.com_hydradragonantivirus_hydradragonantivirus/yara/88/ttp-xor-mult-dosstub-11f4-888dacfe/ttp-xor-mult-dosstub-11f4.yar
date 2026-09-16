rule TTP_XOR_MULT_DOSStub_11f4 {
  strings:
    $key_11f4 = { 45 9c [2] 31 84 [2] 76 86 [2] 31 97 [2] 7f 9b [2] 73 91 [2] 64 9a [2] 7f d4 [2] 42 }

  condition:
    any of them
}