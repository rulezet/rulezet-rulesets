rule TTP_XOR_MULT_DOSStub_8def {
  strings:
    $key_8def = { d9 87 [2] ad 9f [2] ea 9d [2] ad 8c [2] e3 80 [2] ef 8a [2] f8 81 [2] e3 cf [2] de }

  condition:
    any of them
}