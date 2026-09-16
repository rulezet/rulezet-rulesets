rule TTP_XOR_MULT_DOSStub_6ce3 {
  strings:
    $key_6ce3 = { 38 8b [2] 4c 93 [2] 0b 91 [2] 4c 80 [2] 02 8c [2] 0e 86 [2] 19 8d [2] 02 c3 [2] 3f }

  condition:
    any of them
}