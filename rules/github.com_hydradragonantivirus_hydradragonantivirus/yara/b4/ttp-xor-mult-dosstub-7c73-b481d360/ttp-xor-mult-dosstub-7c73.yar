rule TTP_XOR_MULT_DOSStub_7c73 {
  strings:
    $key_7c73 = { 28 1b [2] 5c 03 [2] 1b 01 [2] 5c 10 [2] 12 1c [2] 1e 16 [2] 09 1d [2] 12 53 [2] 2f }

  condition:
    any of them
}