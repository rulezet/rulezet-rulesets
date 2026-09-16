rule TTP_XOR_MULT_DOSStub_457f {
  strings:
    $key_457f = { 11 17 [2] 65 0f [2] 22 0d [2] 65 1c [2] 2b 10 [2] 27 1a [2] 30 11 [2] 2b 5f [2] 16 }

  condition:
    any of them
}