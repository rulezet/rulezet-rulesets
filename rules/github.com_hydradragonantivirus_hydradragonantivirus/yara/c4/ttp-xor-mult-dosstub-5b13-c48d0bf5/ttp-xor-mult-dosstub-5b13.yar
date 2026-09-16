rule TTP_XOR_MULT_DOSStub_5b13 {
  strings:
    $key_5b13 = { 0f 7b [2] 7b 63 [2] 3c 61 [2] 7b 70 [2] 35 7c [2] 39 76 [2] 2e 7d [2] 35 33 [2] 08 }

  condition:
    any of them
}