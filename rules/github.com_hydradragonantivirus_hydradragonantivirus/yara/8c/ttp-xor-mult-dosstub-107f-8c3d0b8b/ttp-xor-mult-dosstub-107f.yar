rule TTP_XOR_MULT_DOSStub_107f {
  strings:
    $key_107f = { 44 17 [2] 30 0f [2] 77 0d [2] 30 1c [2] 7e 10 [2] 72 1a [2] 65 11 [2] 7e 5f [2] 43 }

  condition:
    any of them
}