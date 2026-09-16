rule TTP_XOR_MULT_DOSStub_073f {
  strings:
    $key_073f = { 53 57 [2] 27 4f [2] 60 4d [2] 27 5c [2] 69 50 [2] 65 5a [2] 72 51 [2] 69 1f [2] 54 }

  condition:
    any of them
}