rule TTP_XOR_MULT_DOSStub_0638 {
  strings:
    $key_0638 = { 52 50 [2] 26 48 [2] 61 4a [2] 26 5b [2] 68 57 [2] 64 5d [2] 73 56 [2] 68 18 [2] 55 }

  condition:
    any of them
}