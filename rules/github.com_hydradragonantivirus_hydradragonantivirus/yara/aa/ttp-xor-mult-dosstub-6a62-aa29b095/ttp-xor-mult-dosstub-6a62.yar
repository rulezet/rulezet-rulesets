rule TTP_XOR_MULT_DOSStub_6a62 {
  strings:
    $key_6a62 = { 3e 0a [2] 4a 12 [2] 0d 10 [2] 4a 01 [2] 04 0d [2] 08 07 [2] 1f 0c [2] 04 42 [2] 39 }

  condition:
    any of them
}