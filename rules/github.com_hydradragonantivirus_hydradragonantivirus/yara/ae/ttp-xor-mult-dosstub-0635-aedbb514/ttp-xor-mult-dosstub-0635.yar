rule TTP_XOR_MULT_DOSStub_0635 {
  strings:
    $key_0635 = { 52 5d [2] 26 45 [2] 61 47 [2] 26 56 [2] 68 5a [2] 64 50 [2] 73 5b [2] 68 15 [2] 55 }

  condition:
    any of them
}