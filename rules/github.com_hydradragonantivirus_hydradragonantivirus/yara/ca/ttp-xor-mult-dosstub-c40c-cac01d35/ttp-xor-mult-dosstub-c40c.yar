rule TTP_XOR_MULT_DOSStub_c40c {
  strings:
    $key_c40c = { 90 64 [2] e4 7c [2] a3 7e [2] e4 6f [2] aa 63 [2] a6 69 [2] b1 62 [2] aa 2c [2] 97 }

  condition:
    any of them
}