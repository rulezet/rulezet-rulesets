rule TTP_XOR_MULT_DOSStub_8962 {
  strings:
    $key_8962 = { dd 0a [2] a9 12 [2] ee 10 [2] a9 01 [2] e7 0d [2] eb 07 [2] fc 0c [2] e7 42 [2] da }

  condition:
    any of them
}