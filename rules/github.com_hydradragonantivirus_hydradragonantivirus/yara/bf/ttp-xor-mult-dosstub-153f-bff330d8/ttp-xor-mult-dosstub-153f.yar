rule TTP_XOR_MULT_DOSStub_153f {
  strings:
    $key_153f = { 41 57 [2] 35 4f [2] 72 4d [2] 35 5c [2] 7b 50 [2] 77 5a [2] 60 51 [2] 7b 1f [2] 46 }

  condition:
    any of them
}