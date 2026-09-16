rule TTP_XOR_MULT_DOSStub_647f {
  strings:
    $key_647f = { 30 17 [2] 44 0f [2] 03 0d [2] 44 1c [2] 0a 10 [2] 06 1a [2] 11 11 [2] 0a 5f [2] 37 }

  condition:
    any of them
}