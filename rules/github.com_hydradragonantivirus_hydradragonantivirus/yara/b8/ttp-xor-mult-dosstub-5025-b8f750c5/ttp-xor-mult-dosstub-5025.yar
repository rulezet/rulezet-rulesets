rule TTP_XOR_MULT_DOSStub_5025 {
  strings:
    $key_5025 = { 04 4d [2] 70 55 [2] 37 57 [2] 70 46 [2] 3e 4a [2] 32 40 [2] 25 4b [2] 3e 05 [2] 03 }

  condition:
    any of them
}