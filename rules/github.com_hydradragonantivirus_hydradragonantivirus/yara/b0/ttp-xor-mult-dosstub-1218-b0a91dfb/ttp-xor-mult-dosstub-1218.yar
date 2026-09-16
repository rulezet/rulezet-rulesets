rule TTP_XOR_MULT_DOSStub_1218 {
  strings:
    $key_1218 = { 46 70 [2] 32 68 [2] 75 6a [2] 32 7b [2] 7c 77 [2] 70 7d [2] 67 76 [2] 7c 38 [2] 41 }

  condition:
    any of them
}