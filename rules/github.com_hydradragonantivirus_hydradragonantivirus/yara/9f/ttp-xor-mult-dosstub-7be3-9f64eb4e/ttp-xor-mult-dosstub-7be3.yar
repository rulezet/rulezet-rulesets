rule TTP_XOR_MULT_DOSStub_7be3 {
  strings:
    $key_7be3 = { 2f 8b [2] 5b 93 [2] 1c 91 [2] 5b 80 [2] 15 8c [2] 19 86 [2] 0e 8d [2] 15 c3 [2] 28 }

  condition:
    any of them
}