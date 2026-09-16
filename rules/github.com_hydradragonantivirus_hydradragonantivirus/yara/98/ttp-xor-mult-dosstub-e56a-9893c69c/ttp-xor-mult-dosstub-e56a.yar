rule TTP_XOR_MULT_DOSStub_e56a {
  strings:
    $key_e56a = { b1 02 [2] c5 1a [2] 82 18 [2] c5 09 [2] 8b 05 [2] 87 0f [2] 90 04 [2] 8b 4a [2] b6 }

  condition:
    any of them
}