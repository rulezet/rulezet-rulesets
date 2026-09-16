rule TTP_XOR_MULT_DOSStub_cba6 {
  strings:
    $key_cba6 = { 9f ce [2] eb d6 [2] ac d4 [2] eb c5 [2] a5 c9 [2] a9 c3 [2] be c8 [2] a5 86 [2] 98 }

  condition:
    any of them
}