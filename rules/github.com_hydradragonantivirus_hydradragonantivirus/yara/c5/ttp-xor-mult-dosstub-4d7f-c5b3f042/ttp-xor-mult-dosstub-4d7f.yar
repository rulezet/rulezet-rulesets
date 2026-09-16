rule TTP_XOR_MULT_DOSStub_4d7f {
  strings:
    $key_4d7f = { 19 17 [2] 6d 0f [2] 2a 0d [2] 6d 1c [2] 23 10 [2] 2f 1a [2] 38 11 [2] 23 5f [2] 1e }

  condition:
    any of them
}