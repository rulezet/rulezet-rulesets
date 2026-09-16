rule TTP_XOR_MULT_DOSStub_0109 {
  strings:
    $key_0109 = { 55 61 [2] 21 79 [2] 66 7b [2] 21 6a [2] 6f 66 [2] 63 6c [2] 74 67 [2] 6f 29 [2] 52 }

  condition:
    any of them
}