rule TTP_XOR_MULT_DOSStub_243f {
  strings:
    $key_243f = { 70 57 [2] 04 4f [2] 43 4d [2] 04 5c [2] 4a 50 [2] 46 5a [2] 51 51 [2] 4a 1f [2] 77 }

  condition:
    any of them
}