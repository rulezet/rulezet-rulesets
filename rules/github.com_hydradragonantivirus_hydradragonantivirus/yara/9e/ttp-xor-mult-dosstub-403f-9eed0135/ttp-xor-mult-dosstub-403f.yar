rule TTP_XOR_MULT_DOSStub_403f {
  strings:
    $key_403f = { 14 57 [2] 60 4f [2] 27 4d [2] 60 5c [2] 2e 50 [2] 22 5a [2] 35 51 [2] 2e 1f [2] 13 }

  condition:
    any of them
}