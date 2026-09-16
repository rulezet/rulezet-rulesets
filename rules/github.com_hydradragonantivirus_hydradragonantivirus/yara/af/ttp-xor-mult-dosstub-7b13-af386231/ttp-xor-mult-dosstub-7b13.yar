rule TTP_XOR_MULT_DOSStub_7b13 {
  strings:
    $key_7b13 = { 2f 7b [2] 5b 63 [2] 1c 61 [2] 5b 70 [2] 15 7c [2] 19 76 [2] 0e 7d [2] 15 33 [2] 28 }

  condition:
    any of them
}