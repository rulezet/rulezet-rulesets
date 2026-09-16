rule TTP_XOR_MULT_DOSStub_607f {
  strings:
    $key_607f = { 34 17 [2] 40 0f [2] 07 0d [2] 40 1c [2] 0e 10 [2] 02 1a [2] 15 11 [2] 0e 5f [2] 33 }

  condition:
    any of them
}