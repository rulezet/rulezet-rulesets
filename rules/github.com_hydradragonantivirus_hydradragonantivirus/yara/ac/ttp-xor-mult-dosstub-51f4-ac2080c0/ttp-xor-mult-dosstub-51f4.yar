rule TTP_XOR_MULT_DOSStub_51f4 {
  strings:
    $key_51f4 = { 05 9c [2] 71 84 [2] 36 86 [2] 71 97 [2] 3f 9b [2] 33 91 [2] 24 9a [2] 3f d4 [2] 02 }

  condition:
    any of them
}