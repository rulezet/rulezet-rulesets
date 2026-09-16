rule TTP_XOR_MULT_DOSStub_3ae3 {
  strings:
    $key_3ae3 = { 6e 8b [2] 1a 93 [2] 5d 91 [2] 1a 80 [2] 54 8c [2] 58 86 [2] 4f 8d [2] 54 c3 [2] 69 }

  condition:
    any of them
}