rule TTP_XOR_MULT_DOSStub_1be3 {
  strings:
    $key_1be3 = { 4f 8b [2] 3b 93 [2] 7c 91 [2] 3b 80 [2] 75 8c [2] 79 86 [2] 6e 8d [2] 75 c3 [2] 48 }

  condition:
    any of them
}