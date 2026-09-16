rule TTP_XOR_MULT_DOSStub_cbd2 {
  strings:
    $key_cbd2 = { 9f ba [2] eb a2 [2] ac a0 [2] eb b1 [2] a5 bd [2] a9 b7 [2] be bc [2] a5 f2 [2] 98 }

  condition:
    any of them
}