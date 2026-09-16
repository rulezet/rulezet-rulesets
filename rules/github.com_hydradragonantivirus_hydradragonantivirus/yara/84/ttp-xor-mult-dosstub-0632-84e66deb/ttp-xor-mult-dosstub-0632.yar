rule TTP_XOR_MULT_DOSStub_0632 {
  strings:
    $key_0632 = { 52 5a [2] 26 42 [2] 61 40 [2] 26 51 [2] 68 5d [2] 64 57 [2] 73 5c [2] 68 12 [2] 55 }

  condition:
    any of them
}