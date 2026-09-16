rule TTP_XOR_MULT_DOSStub_24e8 {
  strings:
    $key_24e8 = { 70 80 [2] 04 98 [2] 43 9a [2] 04 8b [2] 4a 87 [2] 46 8d [2] 51 86 [2] 4a c8 [2] 77 }

  condition:
    any of them
}