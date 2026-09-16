rule TTP_XOR_MULT_DOSStub_0113 {
  strings:
    $key_0113 = { 55 7b [2] 21 63 [2] 66 61 [2] 21 70 [2] 6f 7c [2] 63 76 [2] 74 7d [2] 6f 33 [2] 52 }

  condition:
    any of them
}