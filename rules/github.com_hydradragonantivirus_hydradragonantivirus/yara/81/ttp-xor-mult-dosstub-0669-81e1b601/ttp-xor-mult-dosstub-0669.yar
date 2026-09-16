rule TTP_XOR_MULT_DOSStub_0669 {
  strings:
    $key_0669 = { 52 01 [2] 26 19 [2] 61 1b [2] 26 0a [2] 68 06 [2] 64 0c [2] 73 07 [2] 68 49 [2] 55 }

  condition:
    any of them
}