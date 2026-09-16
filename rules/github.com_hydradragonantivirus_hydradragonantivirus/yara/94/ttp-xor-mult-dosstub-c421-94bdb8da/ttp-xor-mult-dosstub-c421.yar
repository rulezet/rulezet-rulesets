rule TTP_XOR_MULT_DOSStub_c421 {
  strings:
    $key_c421 = { 90 49 [2] e4 51 [2] a3 53 [2] e4 42 [2] aa 4e [2] a6 44 [2] b1 4f [2] aa 01 [2] 97 }

  condition:
    any of them
}