rule TTP_XOR_MULT_DOSStub_28e3 {
  strings:
    $key_28e3 = { 7c 8b [2] 08 93 [2] 4f 91 [2] 08 80 [2] 46 8c [2] 4a 86 [2] 5d 8d [2] 46 c3 [2] 7b }

  condition:
    any of them
}