rule TTP_XOR_MULT_DOSStub_c43c {
  strings:
    $key_c43c = { 90 54 [2] e4 4c [2] a3 4e [2] e4 5f [2] aa 53 [2] a6 59 [2] b1 52 [2] aa 1c [2] 97 }

  condition:
    any of them
}