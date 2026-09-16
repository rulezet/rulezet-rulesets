rule TTP_XOR_MULT_DOSStub_0800 {
  strings:
    $key_0800 = { 5c 68 [2] 28 70 [2] 6f 72 [2] 28 63 [2] 66 6f [2] 6a 65 [2] 7d 6e [2] 66 20 [2] 5b }

  condition:
    any of them
}