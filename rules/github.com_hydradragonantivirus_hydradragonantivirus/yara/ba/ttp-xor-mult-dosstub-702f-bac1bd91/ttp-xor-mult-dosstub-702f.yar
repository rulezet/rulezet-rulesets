rule TTP_XOR_MULT_DOSStub_702f {
  strings:
    $key_702f = { 24 47 [2] 50 5f [2] 17 5d [2] 50 4c [2] 1e 40 [2] 12 4a [2] 05 41 [2] 1e 0f [2] 23 }

  condition:
    any of them
}