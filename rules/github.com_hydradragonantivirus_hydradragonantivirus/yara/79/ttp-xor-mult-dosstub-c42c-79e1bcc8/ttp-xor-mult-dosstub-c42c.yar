rule TTP_XOR_MULT_DOSStub_c42c {
  strings:
    $key_c42c = { 90 44 [2] e4 5c [2] a3 5e [2] e4 4f [2] aa 43 [2] a6 49 [2] b1 42 [2] aa 0c [2] 97 }

  condition:
    any of them
}