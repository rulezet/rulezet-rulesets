rule TTP_XOR_MULT_DOSStub_1a3f {
  strings:
    $key_1a3f = { 4e 57 [2] 3a 4f [2] 7d 4d [2] 3a 5c [2] 74 50 [2] 78 5a [2] 6f 51 [2] 74 1f [2] 49 }

  condition:
    any of them
}