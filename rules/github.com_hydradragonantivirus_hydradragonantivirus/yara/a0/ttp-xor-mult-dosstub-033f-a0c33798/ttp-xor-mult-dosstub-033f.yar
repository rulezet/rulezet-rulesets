rule TTP_XOR_MULT_DOSStub_033f {
  strings:
    $key_033f = { 57 57 [2] 23 4f [2] 64 4d [2] 23 5c [2] 6d 50 [2] 61 5a [2] 76 51 [2] 6d 1f [2] 50 }

  condition:
    any of them
}