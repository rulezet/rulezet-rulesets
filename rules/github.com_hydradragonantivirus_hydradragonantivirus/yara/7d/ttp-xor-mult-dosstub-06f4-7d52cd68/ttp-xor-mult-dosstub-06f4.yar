rule TTP_XOR_MULT_DOSStub_06f4 {
  strings:
    $key_06f4 = { 52 9c [2] 26 84 [2] 61 86 [2] 26 97 [2] 68 9b [2] 64 91 [2] 73 9a [2] 68 d4 [2] 55 }

  condition:
    any of them
}