rule TTP_XOR_MULT_DOSStub_27e5 {
  strings:
    $key_27e5 = { 73 8d [2] 07 95 [2] 40 97 [2] 07 86 [2] 49 8a [2] 45 80 [2] 52 8b [2] 49 c5 [2] 74 }

  condition:
    any of them
}