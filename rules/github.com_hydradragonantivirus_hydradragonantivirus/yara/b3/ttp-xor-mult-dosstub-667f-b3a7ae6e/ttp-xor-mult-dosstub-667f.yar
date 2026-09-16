rule TTP_XOR_MULT_DOSStub_667f {
  strings:
    $key_667f = { 32 17 [2] 46 0f [2] 01 0d [2] 46 1c [2] 08 10 [2] 04 1a [2] 13 11 [2] 08 5f [2] 35 }

  condition:
    any of them
}