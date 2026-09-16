rule TTP_XOR_MULT_DOSStub_5062 {
  strings:
    $key_5062 = { 04 0a [2] 70 12 [2] 37 10 [2] 70 01 [2] 3e 0d [2] 32 07 [2] 25 0c [2] 3e 42 [2] 03 }

  condition:
    any of them
}