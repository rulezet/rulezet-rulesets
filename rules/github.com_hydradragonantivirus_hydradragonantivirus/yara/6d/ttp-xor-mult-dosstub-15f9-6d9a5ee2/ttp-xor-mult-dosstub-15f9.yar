rule TTP_XOR_MULT_DOSStub_15f9 {
  strings:
    $key_15f9 = { 41 91 [2] 35 89 [2] 72 8b [2] 35 9a [2] 7b 96 [2] 77 9c [2] 60 97 [2] 7b d9 [2] 46 }

  condition:
    any of them
}