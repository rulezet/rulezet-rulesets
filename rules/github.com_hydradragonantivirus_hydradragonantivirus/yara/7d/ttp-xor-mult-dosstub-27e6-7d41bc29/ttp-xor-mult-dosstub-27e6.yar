rule TTP_XOR_MULT_DOSStub_27e6 {
  strings:
    $key_27e6 = { 73 8e [2] 07 96 [2] 40 94 [2] 07 85 [2] 49 89 [2] 45 83 [2] 52 88 [2] 49 c6 [2] 74 }

  condition:
    any of them
}