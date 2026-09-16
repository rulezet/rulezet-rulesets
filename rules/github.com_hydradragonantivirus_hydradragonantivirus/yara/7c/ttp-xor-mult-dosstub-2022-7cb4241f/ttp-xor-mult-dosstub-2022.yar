rule TTP_XOR_MULT_DOSStub_2022 {
  strings:
    $key_2022 = { 74 4a [2] 00 52 [2] 47 50 [2] 00 41 [2] 4e 4d [2] 42 47 [2] 55 4c [2] 4e 02 [2] 73 }

  condition:
    any of them
}