rule TTP_XOR_MULT_DOSStub_7962 {
  strings:
    $key_7962 = { 2d 0a [2] 59 12 [2] 1e 10 [2] 59 01 [2] 17 0d [2] 1b 07 [2] 0c 0c [2] 17 42 [2] 2a }

  condition:
    any of them
}