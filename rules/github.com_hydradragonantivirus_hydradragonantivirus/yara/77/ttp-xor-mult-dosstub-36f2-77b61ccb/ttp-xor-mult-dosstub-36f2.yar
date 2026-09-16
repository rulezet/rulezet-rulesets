rule TTP_XOR_MULT_DOSStub_36f2 {
  strings:
    $key_36f2 = { 62 9a [2] 16 82 [2] 51 80 [2] 16 91 [2] 58 9d [2] 54 97 [2] 43 9c [2] 58 d2 [2] 65 }

  condition:
    any of them
}