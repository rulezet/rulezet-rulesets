rule TTP_XOR_MULT_DOSStub_4428 {
  strings:
    $key_4428 = { 10 40 [2] 64 58 [2] 23 5a [2] 64 4b [2] 2a 47 [2] 26 4d [2] 31 46 [2] 2a 08 [2] 17 }

  condition:
    any of them
}