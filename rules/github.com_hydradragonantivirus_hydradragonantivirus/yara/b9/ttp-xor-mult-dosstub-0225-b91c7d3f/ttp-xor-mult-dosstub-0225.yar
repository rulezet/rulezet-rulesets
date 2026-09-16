rule TTP_XOR_MULT_DOSStub_0225 {
  strings:
    $key_0225 = { 56 4d [2] 22 55 [2] 65 57 [2] 22 46 [2] 6c 4a [2] 60 40 [2] 77 4b [2] 6c 05 [2] 51 }

  condition:
    any of them
}