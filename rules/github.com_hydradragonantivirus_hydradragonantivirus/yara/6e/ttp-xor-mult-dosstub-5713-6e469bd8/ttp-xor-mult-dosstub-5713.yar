rule TTP_XOR_MULT_DOSStub_5713 {
  strings:
    $key_5713 = { 03 7b [2] 77 63 [2] 30 61 [2] 77 70 [2] 39 7c [2] 35 76 [2] 22 7d [2] 39 33 [2] 04 }

  condition:
    any of them
}