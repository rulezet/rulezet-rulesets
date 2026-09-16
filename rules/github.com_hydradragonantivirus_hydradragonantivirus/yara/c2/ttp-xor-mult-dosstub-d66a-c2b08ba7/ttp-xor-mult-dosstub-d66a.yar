rule TTP_XOR_MULT_DOSStub_d66a {
  strings:
    $key_d66a = { 82 02 [2] f6 1a [2] b1 18 [2] f6 09 [2] b8 05 [2] b4 0f [2] a3 04 [2] b8 4a [2] 85 }

  condition:
    any of them
}