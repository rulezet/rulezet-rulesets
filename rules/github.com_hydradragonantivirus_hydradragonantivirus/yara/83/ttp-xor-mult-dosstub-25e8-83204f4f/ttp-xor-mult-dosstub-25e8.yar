rule TTP_XOR_MULT_DOSStub_25e8 {
  strings:
    $key_25e8 = { 71 80 [2] 05 98 [2] 42 9a [2] 05 8b [2] 4b 87 [2] 47 8d [2] 50 86 [2] 4b c8 [2] 76 }

  condition:
    any of them
}