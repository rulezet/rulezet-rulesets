rule TTP_XOR_MULT_DOSStub_27e2 {
  strings:
    $key_27e2 = { 73 8a [2] 07 92 [2] 40 90 [2] 07 81 [2] 49 8d [2] 45 87 [2] 52 8c [2] 49 c2 [2] 74 }

  condition:
    any of them
}