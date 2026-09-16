rule TTP_XOR_MULT_DOSStub_773f {
  strings:
    $key_773f = { 23 57 [2] 57 4f [2] 10 4d [2] 57 5c [2] 19 50 [2] 15 5a [2] 02 51 [2] 19 1f [2] 24 }

  condition:
    any of them
}