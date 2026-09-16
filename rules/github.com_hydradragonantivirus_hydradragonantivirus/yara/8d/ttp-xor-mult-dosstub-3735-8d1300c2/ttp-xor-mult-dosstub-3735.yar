rule TTP_XOR_MULT_DOSStub_3735 {
  strings:
    $key_3735 = { 63 5d [2] 17 45 [2] 50 47 [2] 17 56 [2] 59 5a [2] 55 50 [2] 42 5b [2] 59 15 [2] 64 }

  condition:
    any of them
}