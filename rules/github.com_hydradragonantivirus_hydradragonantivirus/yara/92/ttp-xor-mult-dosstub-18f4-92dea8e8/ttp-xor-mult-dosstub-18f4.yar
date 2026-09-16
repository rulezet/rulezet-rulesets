rule TTP_XOR_MULT_DOSStub_18f4 {
  strings:
    $key_18f4 = { 4c 9c [2] 38 84 [2] 7f 86 [2] 38 97 [2] 76 9b [2] 7a 91 [2] 6d 9a [2] 76 d4 [2] 4b }

  condition:
    any of them
}