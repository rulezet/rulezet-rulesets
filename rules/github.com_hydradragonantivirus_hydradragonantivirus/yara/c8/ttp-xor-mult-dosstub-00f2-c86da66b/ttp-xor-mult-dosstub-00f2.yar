rule TTP_XOR_MULT_DOSStub_00f2 {
  strings:
    $key_00f2 = { 54 9a [2] 20 82 [2] 67 80 [2] 20 91 [2] 6e 9d [2] 62 97 [2] 75 9c [2] 6e d2 [2] 53 }

  condition:
    any of them
}