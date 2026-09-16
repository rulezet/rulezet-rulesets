rule TTP_XOR_MULT_DOSStub_7e62 {
  strings:
    $key_7e62 = { 2a 0a [2] 5e 12 [2] 19 10 [2] 5e 01 [2] 10 0d [2] 1c 07 [2] 0b 0c [2] 10 42 [2] 2d }

  condition:
    any of them
}