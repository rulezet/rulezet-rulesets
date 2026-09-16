rule TTP_XOR_MULT_DOSStub_6b79 {
  strings:
    $key_6b79 = { 3f 11 [2] 4b 09 [2] 0c 0b [2] 4b 1a [2] 05 16 [2] 09 1c [2] 1e 17 [2] 05 59 [2] 38 }

  condition:
    any of them
}