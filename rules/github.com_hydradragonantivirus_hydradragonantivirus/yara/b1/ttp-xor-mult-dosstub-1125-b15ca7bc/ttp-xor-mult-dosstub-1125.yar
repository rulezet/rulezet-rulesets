rule TTP_XOR_MULT_DOSStub_1125 {
  strings:
    $key_1125 = { 45 4d [2] 31 55 [2] 76 57 [2] 31 46 [2] 7f 4a [2] 73 40 [2] 64 4b [2] 7f 05 [2] 42 }

  condition:
    any of them
}