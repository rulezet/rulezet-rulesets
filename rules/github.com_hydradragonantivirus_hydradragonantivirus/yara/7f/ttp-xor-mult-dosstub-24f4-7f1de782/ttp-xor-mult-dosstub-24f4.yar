rule TTP_XOR_MULT_DOSStub_24f4 {
  strings:
    $key_24f4 = { 70 9c [2] 04 84 [2] 43 86 [2] 04 97 [2] 4a 9b [2] 46 91 [2] 51 9a [2] 4a d4 [2] 77 }

  condition:
    any of them
}