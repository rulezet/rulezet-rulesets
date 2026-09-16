rule TTP_XOR_MULT_DOSStub_0ae8 {
  strings:
    $key_0ae8 = { 5e 80 [2] 2a 98 [2] 6d 9a [2] 2a 8b [2] 64 87 [2] 68 8d [2] 7f 86 [2] 64 c8 [2] 59 }

  condition:
    any of them
}