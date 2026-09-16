rule TTP_XOR_MULT_DOSStub_0871 {
  strings:
    $key_0871 = { 5c 19 [2] 28 01 [2] 6f 03 [2] 28 12 [2] 66 1e [2] 6a 14 [2] 7d 1f [2] 66 51 [2] 5b }

  condition:
    any of them
}