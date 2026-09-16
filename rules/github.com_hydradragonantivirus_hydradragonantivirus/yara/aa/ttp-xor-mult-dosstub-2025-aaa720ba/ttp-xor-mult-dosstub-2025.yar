rule TTP_XOR_MULT_DOSStub_2025 {
  strings:
    $key_2025 = { 74 4d [2] 00 55 [2] 47 57 [2] 00 46 [2] 4e 4a [2] 42 40 [2] 55 4b [2] 4e 05 [2] 73 }

  condition:
    any of them
}