rule TTP_XOR_MULT_DOSStub_18f9 {
  strings:
    $key_18f9 = { 4c 91 [2] 38 89 [2] 7f 8b [2] 38 9a [2] 76 96 [2] 7a 9c [2] 6d 97 [2] 76 d9 [2] 4b }

  condition:
    any of them
}