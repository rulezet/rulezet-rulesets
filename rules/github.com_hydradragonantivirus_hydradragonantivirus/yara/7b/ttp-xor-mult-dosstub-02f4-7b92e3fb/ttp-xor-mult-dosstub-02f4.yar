rule TTP_XOR_MULT_DOSStub_02f4 {
  strings:
    $key_02f4 = { 56 9c [2] 22 84 [2] 65 86 [2] 22 97 [2] 6c 9b [2] 60 91 [2] 77 9a [2] 6c d4 [2] 51 }

  condition:
    any of them
}