rule TTP_XOR_MULT_DOSStub_3e7f {
  strings:
    $key_3e7f = { 6a 17 [2] 1e 0f [2] 59 0d [2] 1e 1c [2] 50 10 [2] 5c 1a [2] 4b 11 [2] 50 5f [2] 6d }

  condition:
    any of them
}