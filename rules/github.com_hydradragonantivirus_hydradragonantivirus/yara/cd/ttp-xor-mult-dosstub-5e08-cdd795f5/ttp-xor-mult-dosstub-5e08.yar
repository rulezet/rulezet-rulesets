rule TTP_XOR_MULT_DOSStub_5e08 {
  strings:
    $key_5e08 = { 0a 60 [2] 7e 78 [2] 39 7a [2] 7e 6b [2] 30 67 [2] 3c 6d [2] 2b 66 [2] 30 28 [2] 0d }

  condition:
    any of them
}