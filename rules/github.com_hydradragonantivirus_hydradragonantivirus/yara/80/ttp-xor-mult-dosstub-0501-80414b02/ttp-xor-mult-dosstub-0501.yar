rule TTP_XOR_MULT_DOSStub_0501 {
  strings:
    $key_0501 = { 51 69 [2] 25 71 [2] 62 73 [2] 25 62 [2] 6b 6e [2] 67 64 [2] 70 6f [2] 6b 21 [2] 56 }

  condition:
    any of them
}