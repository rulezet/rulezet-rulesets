rule TTP_XOR_MULT_DOSStub_0678 {
  strings:
    $key_0678 = { 52 10 [2] 26 08 [2] 61 0a [2] 26 1b [2] 68 17 [2] 64 1d [2] 73 16 [2] 68 58 [2] 55 }

  condition:
    any of them
}