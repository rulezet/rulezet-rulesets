rule TTP_XOR_MULT_DOSStub_5013 {
  strings:
    $key_5013 = { 04 7b [2] 70 63 [2] 37 61 [2] 70 70 [2] 3e 7c [2] 32 76 [2] 25 7d [2] 3e 33 [2] 03 }

  condition:
    any of them
}