rule TTP_XOR_MULT_DOSStub_402f {
  strings:
    $key_402f = { 14 47 [2] 60 5f [2] 27 5d [2] 60 4c [2] 2e 40 [2] 22 4a [2] 35 41 [2] 2e 0f [2] 13 }

  condition:
    any of them
}