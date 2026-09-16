rule TTP_XOR_MULT_DOSStub_c402 {
  strings:
    $key_c402 = { 90 6a [2] e4 72 [2] a3 70 [2] e4 61 [2] aa 6d [2] a6 67 [2] b1 6c [2] aa 22 [2] 97 }

  condition:
    any of them
}