rule TTP_XOR_MULT_DOSStub_36f9 {
  strings:
    $key_36f9 = { 62 91 [2] 16 89 [2] 51 8b [2] 16 9a [2] 58 96 [2] 54 9c [2] 43 97 [2] 58 d9 [2] 65 }

  condition:
    any of them
}