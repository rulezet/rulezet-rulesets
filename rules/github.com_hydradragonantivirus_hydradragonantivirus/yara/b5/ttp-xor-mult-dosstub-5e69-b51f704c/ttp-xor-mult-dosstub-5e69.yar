rule TTP_XOR_MULT_DOSStub_5e69 {
  strings:
    $key_5e69 = { 0a 01 [2] 7e 19 [2] 39 1b [2] 7e 0a [2] 30 06 [2] 3c 0c [2] 2b 07 [2] 30 49 [2] 0d }

  condition:
    any of them
}