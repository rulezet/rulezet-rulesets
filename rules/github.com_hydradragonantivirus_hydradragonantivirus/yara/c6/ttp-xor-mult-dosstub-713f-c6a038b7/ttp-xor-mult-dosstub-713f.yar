rule TTP_XOR_MULT_DOSStub_713f {
  strings:
    $key_713f = { 25 57 [2] 51 4f [2] 16 4d [2] 51 5c [2] 1f 50 [2] 13 5a [2] 04 51 [2] 1f 1f [2] 22 }

  condition:
    any of them
}