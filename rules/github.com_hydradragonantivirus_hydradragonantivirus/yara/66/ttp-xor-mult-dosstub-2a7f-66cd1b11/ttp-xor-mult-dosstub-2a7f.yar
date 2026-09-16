rule TTP_XOR_MULT_DOSStub_2a7f {
  strings:
    $key_2a7f = { 7e 17 [2] 0a 0f [2] 4d 0d [2] 0a 1c [2] 44 10 [2] 48 1a [2] 5f 11 [2] 44 5f [2] 79 }

  condition:
    any of them
}