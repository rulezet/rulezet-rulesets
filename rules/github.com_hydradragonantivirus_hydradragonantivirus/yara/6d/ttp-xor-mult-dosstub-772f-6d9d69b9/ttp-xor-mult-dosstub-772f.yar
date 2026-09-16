rule TTP_XOR_MULT_DOSStub_772f {
  strings:
    $key_772f = { 23 47 [2] 57 5f [2] 10 5d [2] 57 4c [2] 19 40 [2] 15 4a [2] 02 41 [2] 19 0f [2] 24 }

  condition:
    any of them
}