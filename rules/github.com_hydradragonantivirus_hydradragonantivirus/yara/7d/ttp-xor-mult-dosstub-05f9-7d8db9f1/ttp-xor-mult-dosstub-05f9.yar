rule TTP_XOR_MULT_DOSStub_05f9 {
  strings:
    $key_05f9 = { 51 91 [2] 25 89 [2] 62 8b [2] 25 9a [2] 6b 96 [2] 67 9c [2] 70 97 [2] 6b d9 [2] 56 }

  condition:
    any of them
}