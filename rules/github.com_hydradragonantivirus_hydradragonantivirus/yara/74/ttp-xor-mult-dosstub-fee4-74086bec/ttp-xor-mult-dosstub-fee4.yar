rule TTP_XOR_MULT_DOSStub_fee4 {
  strings:
    $key_fee4 = { aa 8c [2] de 94 [2] 99 96 [2] de 87 [2] 90 8b [2] 9c 81 [2] 8b 8a [2] 90 c4 [2] ad }

  condition:
    any of them
}