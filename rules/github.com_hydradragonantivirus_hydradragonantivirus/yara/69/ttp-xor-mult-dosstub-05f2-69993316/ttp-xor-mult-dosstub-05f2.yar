rule TTP_XOR_MULT_DOSStub_05f2 {
  strings:
    $key_05f2 = { 51 9a [2] 25 82 [2] 62 80 [2] 25 91 [2] 6b 9d [2] 67 97 [2] 70 9c [2] 6b d2 [2] 56 }

  condition:
    any of them
}