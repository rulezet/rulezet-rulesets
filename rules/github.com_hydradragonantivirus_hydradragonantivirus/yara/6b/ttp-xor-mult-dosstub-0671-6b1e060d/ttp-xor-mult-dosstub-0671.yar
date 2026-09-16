rule TTP_XOR_MULT_DOSStub_0671 {
  strings:
    $key_0671 = { 52 19 [2] 26 01 [2] 61 03 [2] 26 12 [2] 68 1e [2] 64 14 [2] 73 1f [2] 68 51 [2] 55 }

  condition:
    any of them
}