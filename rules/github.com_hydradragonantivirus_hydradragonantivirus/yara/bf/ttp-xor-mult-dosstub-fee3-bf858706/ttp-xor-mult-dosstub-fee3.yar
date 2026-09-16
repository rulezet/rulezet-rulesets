rule TTP_XOR_MULT_DOSStub_fee3 {
  strings:
    $key_fee3 = { aa 8b [2] de 93 [2] 99 91 [2] de 80 [2] 90 8c [2] 9c 86 [2] 8b 8d [2] 90 c3 [2] ad }

  condition:
    any of them
}