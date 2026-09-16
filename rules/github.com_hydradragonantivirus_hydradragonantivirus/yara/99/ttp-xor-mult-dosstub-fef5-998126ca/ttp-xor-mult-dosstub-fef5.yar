rule TTP_XOR_MULT_DOSStub_fef5 {
  strings:
    $key_fef5 = { aa 9d [2] de 85 [2] 99 87 [2] de 96 [2] 90 9a [2] 9c 90 [2] 8b 9b [2] 90 d5 [2] ad }

  condition:
    any of them
}