rule TTP_XOR_MULT_DOSStub_5e7f {
  strings:
    $key_5e7f = { 0a 17 [2] 7e 0f [2] 39 0d [2] 7e 1c [2] 30 10 [2] 3c 1a [2] 2b 11 [2] 30 5f [2] 0d }

  condition:
    any of them
}