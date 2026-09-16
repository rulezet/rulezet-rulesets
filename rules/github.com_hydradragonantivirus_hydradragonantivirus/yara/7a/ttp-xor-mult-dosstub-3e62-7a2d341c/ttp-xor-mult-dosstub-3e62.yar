rule TTP_XOR_MULT_DOSStub_3e62 {
  strings:
    $key_3e62 = { 6a 0a [2] 1e 12 [2] 59 10 [2] 1e 01 [2] 50 0d [2] 5c 07 [2] 4b 0c [2] 50 42 [2] 6d }

  condition:
    any of them
}