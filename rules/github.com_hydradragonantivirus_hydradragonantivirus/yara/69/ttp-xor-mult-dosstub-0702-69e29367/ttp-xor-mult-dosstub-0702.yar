rule TTP_XOR_MULT_DOSStub_0702 {
  strings:
    $key_0702 = { 53 6a [2] 27 72 [2] 60 70 [2] 27 61 [2] 69 6d [2] 65 67 [2] 72 6c [2] 69 22 [2] 54 }

  condition:
    any of them
}