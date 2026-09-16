rule TTP_XOR_MULT_DOSStub_7b3f {
  strings:
    $key_7b3f = { 2f 57 [2] 5b 4f [2] 1c 4d [2] 5b 5c [2] 15 50 [2] 19 5a [2] 0e 51 [2] 15 1f [2] 28 }

  condition:
    any of them
}