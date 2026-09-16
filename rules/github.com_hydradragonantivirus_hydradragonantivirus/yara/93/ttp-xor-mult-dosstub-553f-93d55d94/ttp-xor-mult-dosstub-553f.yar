rule TTP_XOR_MULT_DOSStub_553f {
  strings:
    $key_553f = { 01 57 [2] 75 4f [2] 32 4d [2] 75 5c [2] 3b 50 [2] 37 5a [2] 20 51 [2] 3b 1f [2] 06 }

  condition:
    any of them
}