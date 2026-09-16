rule TTP_XOR_MULT_DOSStub_12f4 {
  strings:
    $key_12f4 = { 46 9c [2] 32 84 [2] 75 86 [2] 32 97 [2] 7c 9b [2] 70 91 [2] 67 9a [2] 7c d4 [2] 41 }

  condition:
    any of them
}