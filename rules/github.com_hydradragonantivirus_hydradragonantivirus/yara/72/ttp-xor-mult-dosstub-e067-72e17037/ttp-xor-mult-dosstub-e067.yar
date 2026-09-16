rule TTP_XOR_MULT_DOSStub_e067 {
  strings:
    $key_e067 = { b4 0f [2] c0 17 [2] 87 15 [2] c0 04 [2] 8e 08 [2] 82 02 [2] 95 09 [2] 8e 47 [2] b3 }

  condition:
    any of them
}