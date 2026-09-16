rule TTP_XOR_MULT_DOSStub_cbe7 {
  strings:
    $key_cbe7 = { 9f 8f [2] eb 97 [2] ac 95 [2] eb 84 [2] a5 88 [2] a9 82 [2] be 89 [2] a5 c7 [2] 98 }

  condition:
    any of them
}