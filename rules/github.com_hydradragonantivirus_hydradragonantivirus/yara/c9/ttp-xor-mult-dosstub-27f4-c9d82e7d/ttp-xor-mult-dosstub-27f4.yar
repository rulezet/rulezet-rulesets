rule TTP_XOR_MULT_DOSStub_27f4 {
  strings:
    $key_27f4 = { 73 9c [2] 07 84 [2] 40 86 [2] 07 97 [2] 49 9b [2] 45 91 [2] 52 9a [2] 49 d4 [2] 74 }

  condition:
    any of them
}