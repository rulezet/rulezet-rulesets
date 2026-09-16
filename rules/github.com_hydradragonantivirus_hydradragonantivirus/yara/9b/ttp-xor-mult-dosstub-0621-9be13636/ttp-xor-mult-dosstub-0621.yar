rule TTP_XOR_MULT_DOSStub_0621 {
  strings:
    $key_0621 = { 52 49 [2] 26 51 [2] 61 53 [2] 26 42 [2] 68 4e [2] 64 44 [2] 73 4f [2] 68 01 [2] 55 }

  condition:
    any of them
}