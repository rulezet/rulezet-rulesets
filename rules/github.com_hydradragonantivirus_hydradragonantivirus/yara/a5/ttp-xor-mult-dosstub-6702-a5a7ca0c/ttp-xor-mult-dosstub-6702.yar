rule TTP_XOR_MULT_DOSStub_6702 {
  strings:
    $key_6702 = { 33 6a [2] 47 72 [2] 00 70 [2] 47 61 [2] 09 6d [2] 05 67 [2] 12 6c [2] 09 22 [2] 34 }

  condition:
    any of them
}