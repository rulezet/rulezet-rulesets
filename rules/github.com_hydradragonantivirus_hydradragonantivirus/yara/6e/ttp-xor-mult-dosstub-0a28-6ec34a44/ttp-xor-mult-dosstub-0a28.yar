rule TTP_XOR_MULT_DOSStub_0a28 {
  strings:
    $key_0a28 = { 5e 40 [2] 2a 58 [2] 6d 5a [2] 2a 4b [2] 64 47 [2] 68 4d [2] 7f 46 [2] 64 08 [2] 59 }

  condition:
    any of them
}