rule TTP_XOR_MULT_DOSStub_0619 {
  strings:
    $key_0619 = { 52 71 [2] 26 69 [2] 61 6b [2] 26 7a [2] 68 76 [2] 64 7c [2] 73 77 [2] 68 39 [2] 55 }

  condition:
    any of them
}