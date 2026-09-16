rule TTP_XOR_MULT_DOSStub_6228 {
  strings:
    $key_6228 = { 36 40 [2] 42 58 [2] 05 5a [2] 42 4b [2] 0c 47 [2] 00 4d [2] 17 46 [2] 0c 08 [2] 31 }

  condition:
    any of them
}