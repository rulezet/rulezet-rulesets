rule TTP_XOR_MULT_DOSStub_6225 {
  strings:
    $key_6225 = { 36 4d [2] 42 55 [2] 05 57 [2] 42 46 [2] 0c 4a [2] 00 40 [2] 17 4b [2] 0c 05 [2] 31 }

  condition:
    any of them
}