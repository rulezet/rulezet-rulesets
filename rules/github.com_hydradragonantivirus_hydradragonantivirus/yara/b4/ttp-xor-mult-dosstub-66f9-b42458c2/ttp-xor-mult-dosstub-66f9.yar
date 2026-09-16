rule TTP_XOR_MULT_DOSStub_66f9 {
  strings:
    $key_66f9 = { 32 91 [2] 46 89 [2] 01 8b [2] 46 9a [2] 08 96 [2] 04 9c [2] 13 97 [2] 08 d9 [2] 35 }

  condition:
    any of them
}