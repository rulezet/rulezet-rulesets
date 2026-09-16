rule TTP_XOR_MULT_DOSStub_5b74 {
  strings:
    $key_5b74 = { 0f 1c [2] 7b 04 [2] 3c 06 [2] 7b 17 [2] 35 1b [2] 39 11 [2] 2e 1a [2] 35 54 [2] 08 }

  condition:
    any of them
}