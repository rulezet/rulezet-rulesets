rule TTP_XOR_MULT_DOSStub_4c7f {
  strings:
    $key_4c7f = { 18 17 [2] 6c 0f [2] 2b 0d [2] 6c 1c [2] 22 10 [2] 2e 1a [2] 39 11 [2] 22 5f [2] 1f }

  condition:
    any of them
}