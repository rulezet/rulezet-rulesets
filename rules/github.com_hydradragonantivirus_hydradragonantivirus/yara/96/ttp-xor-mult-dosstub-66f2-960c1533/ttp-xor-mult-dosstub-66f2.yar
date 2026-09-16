rule TTP_XOR_MULT_DOSStub_66f2 {
  strings:
    $key_66f2 = { 32 9a [2] 46 82 [2] 01 80 [2] 46 91 [2] 08 9d [2] 04 97 [2] 13 9c [2] 08 d2 [2] 35 }

  condition:
    any of them
}