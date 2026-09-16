rule TTP_XOR_MULT_DOSStub_1024 {
  strings:
    $key_1024 = { 44 4c [2] 30 54 [2] 77 56 [2] 30 47 [2] 7e 4b [2] 72 41 [2] 65 4a [2] 7e 04 [2] 43 }

  condition:
    any of them
}