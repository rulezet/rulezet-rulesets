rule TTP_XOR_MULT_DOSStub_1e62 {
  strings:
    $key_1e62 = { 4a 0a [2] 3e 12 [2] 79 10 [2] 3e 01 [2] 70 0d [2] 7c 07 [2] 6b 0c [2] 70 42 [2] 4d }

  condition:
    any of them
}