rule TTP_XOR_MULT_DOSStub_24f9 {
  strings:
    $key_24f9 = { 70 91 [2] 04 89 [2] 43 8b [2] 04 9a [2] 4a 96 [2] 46 9c [2] 51 97 [2] 4a d9 [2] 77 }

  condition:
    any of them
}