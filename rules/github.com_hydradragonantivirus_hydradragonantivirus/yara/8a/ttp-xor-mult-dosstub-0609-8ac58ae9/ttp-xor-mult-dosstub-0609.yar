rule TTP_XOR_MULT_DOSStub_0609 {
  strings:
    $key_0609 = { 52 61 [2] 26 79 [2] 61 7b [2] 26 6a [2] 68 66 [2] 64 6c [2] 73 67 [2] 68 29 [2] 55 }

  condition:
    any of them
}