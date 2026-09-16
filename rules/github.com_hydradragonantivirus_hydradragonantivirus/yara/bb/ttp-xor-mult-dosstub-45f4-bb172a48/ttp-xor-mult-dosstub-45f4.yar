rule TTP_XOR_MULT_DOSStub_45f4 {
  strings:
    $key_45f4 = { 11 9c [2] 65 84 [2] 22 86 [2] 65 97 [2] 2b 9b [2] 27 91 [2] 30 9a [2] 2b d4 [2] 16 }

  condition:
    any of them
}