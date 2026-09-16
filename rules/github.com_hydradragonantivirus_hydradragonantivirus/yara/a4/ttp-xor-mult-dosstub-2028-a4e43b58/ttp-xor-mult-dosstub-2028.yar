rule TTP_XOR_MULT_DOSStub_2028 {
  strings:
    $key_2028 = { 74 40 [2] 00 58 [2] 47 5a [2] 00 4b [2] 4e 47 [2] 42 4d [2] 55 46 [2] 4e 08 [2] 73 }

  condition:
    any of them
}